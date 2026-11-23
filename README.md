# Certificate Observation Records

Working repository for the Internet-Draft
**draft-barcelo-opsawg-cert-observation**, *An Information Model and JSON
Encoding for Certificate Observation Records*, and example code that produces
those records.

> This is an individual Internet-Draft. It has not been adopted by any IETF
> working group and is not an IETF standard.

## The idea in one paragraph

Operators need to know which X.509 certificates are installed where, when they
expire, and whether a renewed certificate actually reached the service that
uses it. That knowledge is spread across network observers, local agents,
configuration management systems and issuers, each with its own format, and
many endpoints cannot be reached by a central monitor at all. A *Certificate
Observation Record* is a small JSON statement: *reporter R saw certificate C at
location L of subject S, with evidence type E, at time T*. Because the reporter
and the subject are separate, one system can report on behalf of endpoints the
collector cannot reach; because each record carries an evidence type
(`issued`, `declared`, `deployed`, `observed-store`, `observed-wire`), a
collector can detect when issuance, deployment and the running service diverge.

## Layout

| Path | Contents |
|---|---|
| `draft/` | Draft source (xml2rfc v3). `make draft` renders text and HTML. |
| `schema/cert-observation.cddl` | CDDL from the draft (normative). |
| `schema/cert-observation.schema.json` | JSON Schema equivalent, for tooling. |
| `examples/records/` | Example record sets taken from the draft. |
| `tools/python/` | Reference producer (`cor_observe.py`) and validator (`cor_validate.py`). |
| `tools/bash/` | Minimal producer using only `openssl` and `jq`. |
| `tools/powershell/` | Producer for the Windows certificate store. |
| `tests/` | Tests: examples and generated records validate against the schema. |

## Quick start

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r tools/python/requirements.txt pytest xml2rfc

# Network observer (TLS handshake)
python3 tools/python/cor_observe.py wire www.example.net:443 --service https

# Local agent: certificate files or directories, written for file-based handoff
python3 tools/python/cor_observe.py store /etc/pki/tls/certs --out /var/spool/cor/host.cor.json

# Push to a collector
python3 tools/python/cor_observe.py --push https://collector.example.net/cor \
    --token-file /etc/cor/token wire www.example.net

# Validate any record set
python3 tools/python/cor_validate.py examples/records/*.json

# Build the draft and run the tests
make draft test
```

Bash (needs OpenSSL 3.x and `jq`):

```sh
tools/bash/cor-observe.sh wire www.example.net:443
COR_OUT=/var/spool/cor/host.cor.json tools/bash/cor-observe.sh store /etc/ssl/certs/server.pem
```

PowerShell (Windows certificate store; `-UseDefaultCredentials` pushes with
Kerberos/Negotiate):

```powershell
.\tools\powershell\Get-CertObservation.ps1 -StorePath Cert:\LocalMachine\My `
    -PushUri https://collector.example.net/cor -UseDefaultCredentials
```

## Status

| Component | State |
|---|---|
| Draft `-00` | Written, not yet submitted to the Datatracker |
| Python producer | `wire` and `store` modes, tested |
| Bash producer | `wire` and `store` modes, tested |
| PowerShell producer | Written, **not yet tested on Windows** |
| Collector / correlation | Not started |
| Configuration-management (proxy) reporter | Not started |

## Contributing

Discussion of the draft belongs on the OPSAWG mailing list
(opsawg@ietf.org) once it is posted. Issues and pull requests here are welcome
for the code and for editorial fixes.

Contributions to the draft are subject to the
[IETF Note Well](https://www.ietf.org/about/note-well/).

## License

Code: BSD 3-Clause (see `LICENSE`), the same licence the IETF Trust applies to
code components in Internet-Drafts. Draft text: once submitted, subject to the
IETF Trust Legal Provisions (BCP 78).
