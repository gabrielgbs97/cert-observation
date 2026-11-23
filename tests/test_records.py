"""Tests: draft examples and generated records validate against the JSON Schema."""
import datetime as dt
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "python"))
import cor_observe  # noqa: E402

VALIDATOR = Draft202012Validator(
    json.loads((ROOT / "schema" / "cert-observation.schema.json").read_text()),
    format_checker=FormatChecker(),
)


def make_cert(path: Path, days: int = 30, offset_days: int = -1) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.net")])
    start = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=offset_days)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(start + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.example.net")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert.fingerprint(hashes.SHA256()).hex()


@pytest.mark.parametrize("example", sorted((ROOT / "examples" / "records").glob("*.json")))
def test_examples_valid(example):
    errors = list(VALIDATOR.iter_errors(json.loads(example.read_text())))
    assert not errors, [e.message for e in errors]


def test_store_mode(tmp_path, capsys):
    fp = make_cert(tmp_path / "server.pem")
    out = tmp_path / "spool" / "host.cor.json"
    assert cor_observe.main(["--reporter", "agent.example.net", "--out", str(out), "--quiet",
                             "store", str(tmp_path)]) == 0
    data = json.loads(out.read_text())
    assert not list(VALIDATOR.iter_errors(data))
    rec = data["records"][0]
    assert rec["evidence"] == "observed-store"
    assert rec["certificate"]["sha256"] == fp
    assert rec["certificate"]["san"] == ["test.example.net"]
    assert "status" not in rec


def test_expired_and_expected_mismatch(tmp_path, capsys):
    make_cert(tmp_path / "old.pem", days=1, offset_days=-10)
    assert cor_observe.main(["--expected-sha256", "0" * 64, "store", str(tmp_path / "old.pem")]) == 0
    data = json.loads(capsys.readouterr().out)
    assert not list(VALIDATOR.iter_errors(data))
    assert data["records"][0]["status"] == ["expired", "unexpected-certificate"]


def test_minimise_omits_names(tmp_path, capsys):
    make_cert(tmp_path / "client.pem")
    assert cor_observe.main(["--minimise", "store", str(tmp_path)]) == 0
    cert = json.loads(capsys.readouterr().out)["records"][0]["certificate"]
    assert "subject-dn" not in cert and "san" not in cert


def test_not_found(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    assert cor_observe.main(["store", "--expect", str(tmp_path / "empty")]) == 0
    data = json.loads(capsys.readouterr().out)
    assert not list(VALIDATOR.iter_errors(data))
    assert data["records"][0]["status"] == ["not-found"]


@pytest.mark.skipif(not (shutil.which("jq") and shutil.which("openssl")), reason="needs jq and openssl")
def test_bash_store(tmp_path):
    fp = make_cert(tmp_path / "server.pem")
    res = subprocess.run(["bash", str(ROOT / "tools" / "bash" / "cor-observe.sh"), "store", str(tmp_path / "server.pem")],
                         capture_output=True, text=True, check=True, env={"COR_REPORTER": "agent.example.net", "PATH": "/usr/bin:/bin:/usr/local/bin"})
    data = json.loads(res.stdout)
    assert not list(VALIDATOR.iter_errors(data)), list(VALIDATOR.iter_errors(data))
    assert data["records"][0]["certificate"]["sha256"] == fp
