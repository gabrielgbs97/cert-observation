#!/usr/bin/env python3
"""Produce Certificate Observation Records (draft-barcelo-opsawg-cert-observation).

Two reporter modes:

  wire   Network observer: TLS handshake with host:port, evidence "observed-wire".
  store  Local agent: read PEM/DER files or directories, evidence "observed-store".

Output: a cert-observation-set (JSON) written to stdout, to a file (atomic
write, for file-based handoff) and/or pushed to a collector with HTTP POST.

Examples:
  cor_observe.py wire www.example.net:443 imap.example.net:993
  cor_observe.py store /etc/pki/tls/certs/server.pem --out /var/spool/cor/host.cor.json
  cor_observe.py wire www.example.net --push https://collector.example.net/cor --token-file /etc/cor/token
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import socket
import ssl
import sys
import tempfile
import urllib.request
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

MEDIA_TYPE = "application/cert-observation+json"
VERSION = 1


# --------------------------------------------------------------------------- helpers

def utc(ts: dt.datetime) -> str:
    """RFC 3339 UTC timestamp with 'Z'."""
    return ts.astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def sha256_hex(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {key.curve.name}", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    # Unknown to this library version (for example ML-DSA): report the OID.
    return cert.public_key_algorithm_oid.dotted_string, None


def san_list(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    names: list[str] = []
    names += ext.get_values_for_type(x509.DNSName)
    names += [str(ip) for ip in ext.get_values_for_type(x509.IPAddress)]
    names += ext.get_values_for_type(x509.RFC822Name)
    names += ext.get_values_for_type(x509.UniformResourceIdentifier)
    return names


def certificate_info(cert: x509.Certificate, include_der: bool, include_names: bool = True) -> dict:
    der = cert.public_bytes(serialization.Encoding.DER)
    alg, size = key_info(cert)
    info: dict = {"sha256": sha256_hex(der)}
    if include_names:
        info["subject-dn"] = cert.subject.rfc4514_string()
        sans = san_list(cert)
        if sans:
            info["san"] = sans
    info["issuer-dn"] = cert.issuer.rfc4514_string()
    info["serial"] = format(cert.serial_number, "x")
    info["not-before"] = utc(cert.not_valid_before_utc)
    info["not-after"] = utc(cert.not_valid_after_utc)
    info["public-key-algorithm"] = alg
    if size:
        info["public-key-size"] = size
    sig = cert.signature_algorithm_oid
    info["signature-algorithm"] = getattr(sig, "_name", None) or sig.dotted_string
    if include_der:
        info["der"] = base64.b64encode(der).decode("ascii")
    return info


def validity_status(cert: x509.Certificate) -> list[str]:
    t = now()
    if t > cert.not_valid_after_utc:
        return ["expired"]
    if t < cert.not_valid_before_utc:
        return ["not-yet-valid"]
    return []


def base_record(args, subject: dict, location: dict, evidence: str) -> dict:
    rec = {
        "version": VERSION,
        "record-id": str(uuid.uuid4()),
        "reporter": args.reporter,
        "subject": subject,
        "location": location,
        "evidence": evidence,
        "observed-at": utc(now()),
    }
    if args.valid_for is not None:
        rec["valid-for"] = args.valid_for
    return rec


def finish(rec: dict, status: list[str], args) -> dict:
    if args.expected_sha256 and "certificate" in rec:
        rec["expected-sha256"] = args.expected_sha256.lower()
        if rec["certificate"]["sha256"] != rec["expected-sha256"]:
            status.append("unexpected-certificate")
    if status:
        rec["status"] = sorted(set(status))
    return rec


# --------------------------------------------------------------------------- wire mode

def parse_target(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):  # [IPv6]:port
        host, _, rest = target[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if target.count(":") == 1:
        host, port = target.split(":")
        return host, int(port)
    return target, default_port


def fetch_chain(host: str, port: int, sni: str | None, timeout: float, verify: bool, cafile: str | None):
    """Return (leaf_der, chain_ders, peer_address)."""
    if verify:
        ctx = ssl.create_default_context(cafile=cafile)
        ctx.check_hostname = bool(sni)
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        peer = raw.getpeername()[0]
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            leaf = tls.getpeercert(binary_form=True)
            chain: list[bytes] = []
            getter = getattr(tls, "get_unverified_chain", None)  # Python 3.13+
            if getter:
                chain = [c if isinstance(c, bytes) else c.public_bytes(ssl.ENCODING_DER)
                         for c in getter()][1:]
            return leaf, chain, peer


def observe_wire(args) -> list[dict]:
    records = []
    for target in args.targets:
        host, port = parse_target(target, args.port)
        sni = None if args.no_sni else (args.sni or host)
        subject = {"host": host}
        if args.service:
            subject["service"] = args.service
        location = {"port": port}
        if sni:
            location["sni"] = sni
        rec = base_record(args, subject, location, "observed-wire")
        status: list[str] = []
        try:
            try:
                leaf, chain, peer = fetch_chain(host, port, sni, args.timeout, True, args.cafile)
                validation = "valid"
            except ssl.SSLCertVerificationError as exc:
                if "hostname" in str(exc).lower() or "ip address mismatch" in str(exc).lower():
                    status.append("name-mismatch")
                else:
                    status.append("chain-invalid")
                validation = "invalid"
                leaf, chain, peer = fetch_chain(host, port, sni, args.timeout, False, None)
        except (OSError, ssl.SSLError) as exc:
            print(f"warning: {target}: {exc}", file=sys.stderr)
            rec["status"] = ["not-found"]
            rec["extensions"] = {"error": str(exc)}
            records.append(rec)
            continue
        rec["location"]["address"] = peer
        cert = x509.load_der_x509_certificate(leaf)
        rec["certificate"] = certificate_info(cert, args.include_der, not args.minimise)
        chain_info: dict = {"validation": validation}
        if chain:
            chain_info["certificates"] = [sha256_hex(c) for c in chain]
        rec["chain"] = chain_info
        status += validity_status(cert)
        records.append(finish(rec, status, args))
    return records


# --------------------------------------------------------------------------- store mode

def load_certs(path: Path) -> list[x509.Certificate]:
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificates(data)
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        return []


def iter_files(paths: list[str], patterns: list[str]):
    for p in map(Path, paths):
        if p.is_dir():
            for pattern in patterns:
                yield from sorted(p.rglob(pattern))
        else:
            yield p


def observe_store(args) -> list[dict]:
    records = []
    subject = {"host": args.subject or args.reporter}
    seen: set[Path] = set()
    for path in iter_files(args.paths, args.pattern):
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            certs = load_certs(path)
        except (OSError, ValueError) as exc:
            print(f"warning: {path}: {exc}", file=sys.stderr)
            continue
        if not certs:
            continue  # not a certificate file (for example a private key)
        rec = base_record(args, dict(subject), {"path": str(path.resolve())}, "observed-store")
        leaf, chain = certs[0], certs[1:]
        rec["certificate"] = certificate_info(leaf, args.include_der, not args.minimise)
        chain_info: dict = {"validation": "not-checked"}
        if chain:
            chain_info["certificates"] = [sha256_hex(c.public_bytes(serialization.Encoding.DER)) for c in chain]
        rec["chain"] = chain_info
        records.append(finish(rec, validity_status(leaf), args))
    if not records and args.expect:
        rec = base_record(args, dict(subject), {"path": str(Path(args.paths[0]).resolve())}, "observed-store")
        rec["status"] = ["not-found"]
        records.append(rec)
    return records


# --------------------------------------------------------------------------- output

def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cor-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def push(url: str, body: bytes, token: str | None, timeout: float) -> int:
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": MEDIA_TYPE})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reporter", default=socket.getfqdn(), help="reporter identifier (default: local FQDN)")
    ap.add_argument("--valid-for", type=int, default=3600, help="seconds the record stays current (default 3600)")
    ap.add_argument("--expected-sha256", help="fingerprint that should be found; mismatch adds 'unexpected-certificate'")
    ap.add_argument("--include-der", action="store_true", help="include base64 DER of the certificate")
    ap.add_argument("--minimise", action="store_true", help="omit subject DN and SANs (privacy, client certificates)")
    ap.add_argument("--out", type=Path, help="write record set atomically to this file (use .cor.json)")
    ap.add_argument("--push", metavar="URL", help="POST record set to a collector")
    ap.add_argument("--token-file", type=Path, help="file with a bearer token for --push")
    ap.add_argument("--quiet", action="store_true", help="do not print the record set to stdout")
    sub = ap.add_subparsers(dest="mode", required=True)

    w = sub.add_parser("wire", help="network observer (TLS handshake)")
    w.add_argument("targets", nargs="+", help="host[:port], [ipv6]:port")
    w.add_argument("--port", type=int, default=443)
    w.add_argument("--sni", help="override SNI (default: the host)")
    w.add_argument("--no-sni", action="store_true")
    w.add_argument("--service", help="service name for the subject, e.g. https")
    w.add_argument("--cafile", help="trust anchors for chain validation (default: system store)")
    w.add_argument("--timeout", type=float, default=10.0)

    s = sub.add_parser("store", help="local agent (files and directories)")
    s.add_argument("paths", nargs="+")
    s.add_argument("--pattern", action="append", default=None,
                   help="glob for directories (repeatable; default *.pem *.crt *.cer)")
    s.add_argument("--subject", help="subject host (default: the reporter)")
    s.add_argument("--expect", action="store_true", help="emit a 'not-found' record if nothing is found")

    args = ap.parse_args(argv)
    if args.mode == "store" and not args.pattern:
        args.pattern = ["*.pem", "*.crt", "*.cer"]

    records = observe_wire(args) if args.mode == "wire" else observe_store(args)
    if not records:
        print("no certificates found", file=sys.stderr)
        return 1
    text = json.dumps({"version": VERSION, "records": records}, indent=2) + "\n"

    if not args.quiet:
        sys.stdout.write(text)
    if args.out:
        write_atomic(args.out, text)
    if args.push:
        token = args.token_file.read_text().strip() if args.token_file else None
        status = push(args.push, text.encode(), token, 30.0)
        print(f"pushed {len(records)} record(s): HTTP {status}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
