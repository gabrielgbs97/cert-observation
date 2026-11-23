# CLAUDE.md — context for Claude Code

Context carried over from the Cowork conversation where this repository was
created (23 November 2026). Read this before working on the repo.

## What this is

- Individual IETF Internet-Draft `draft-barcelo-opsawg-cert-observation-00`
  (source: `draft/draft-barcelo-opsawg-cert-observation.xml`, xml2rfc v3),
  intended for OPSAWG, intended status Standards Track. Not yet submitted.
- Author: Gabriel Barceló Soteras, systems administrator. The problem comes
  from his real operational experience (short certificate lifetimes, devices
  that cannot run ACME, endpoints the monitor cannot reach).
- Example producers in Python, Bash and PowerShell, plus a JSON Schema and
  tests.

## Design decisions already taken

- Record = reporter + subject + location + evidence type + observed-at.
  Reporter and subject are separate so a configuration management system can
  report on behalf of endpoints the collector cannot reach ("proxy reporting").
- Evidence types: `issued`, `declared`, `deployed`, `observed-store`,
  `observed-wire`. Collectors correlate them to find "deployed but not loaded",
  "issued but not deployed", etc.
- Freshness via `valid-for` (seconds); stale records must not count as proof.
- Transport-independent information model; this draft defines JSON + HTTP
  push/pull + file-based handoff. YANG, SNMP (MIB likely informational/vendor,
  IETF prefers YANG) and CBOR are future bindings.
- Security: authenticate reporters, authorise reporter→subject, never include
  private keys. HTTP Negotiate (Kerberos, RFC 4559) is a good reporter
  authentication option in AD environments; JWS signing only for end-to-end
  integrity through intermediaries.
- Language in the draft is generic (no product names). Product names may only
  appear in the Implementation Status section (RFC 7942).

## Open TODOs for the draft

- [ ] Verify the RFC 9773 reference (authors, date) and add its DOI `10.17487/RFC9773`.
- [ ] Introduction: mention SC-081 DCV reuse of 10 days from 2029 and that some
      CAs already issue ~6-day certificates (Let's Encrypt `shortlived` profile,
      GA 2026-01-15); add a reference.
- [ ] Section "Other Bindings": shorten to one sentence in Scope and move the
      list + the CBOM remark to the Open Issues appendix (or cite CBOM).
- [ ] Security Considerations: list HTTP Negotiate (RFC 4559) as an option
      for reporter authentication.
- [ ] Decide author name form in header: "G. Barceló Soteras" (current) or
      "G. Barceló".
- [ ] Consider an Acknowledgments line disclosing AI-assisted drafting; the
      author must review and rewrite text in his own words before submission.
- [ ] Run `idnits` and a CDDL validator (`cddl` gem) before submitting.
- [ ] Keep `schema/cert-observation.cddl` in sync with the draft's CDDL.

## Open TODOs for the code

- [ ] Test `tools/powershell/Get-CertObservation.ps1` on Windows (PS 5.1 and 7).
- [ ] Proxy reporter for a configuration management system (evidence
      `declared` / `deployed`), e.g. an Ansible module or callback.
- [ ] Minimal collector that accepts HTTP push and correlates evidence types.
- [ ] Exporter / local check for an open-source monitoring system (agent spool
      directory) as "running code" for the Implementation Status section.

## Conventions

- Public repo: English for code, comments and docs.
- `make test` (pytest), `make validate` (examples vs schema), `make draft`
  (needs `xml2rfc`). CI in `.github/workflows/ci.yml` also runs shellcheck.
- Commit messages: imperative mood, short subject line.
