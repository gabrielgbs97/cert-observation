#!/usr/bin/env bash
# cor-observe.sh - minimal Certificate Observation Record producer (openssl + jq).
#
#   cor-observe.sh wire  host[:port] [...]     evidence "observed-wire"
#   cor-observe.sh store file.pem [...]        evidence "observed-store"
#
# Environment:
#   COR_REPORTER   reporter identifier (default: hostname -f)
#   COR_VALID_FOR  seconds the record stays current (default: 3600)
#   COR_OUT        write the record set atomically to this file (.cor.json)
#   COR_PUSH_URL   POST the record set to a collector (curl)
#   COR_TOKEN      bearer token for COR_PUSH_URL
#
# Requires OpenSSL >= 3.0 (for -dateopt iso_8601) and jq.
set -euo pipefail

MEDIA_TYPE="application/cert-observation+json"
REPORTER="${COR_REPORTER:-$(hostname -f 2>/dev/null || hostname)}"
VALID_FOR="${COR_VALID_FOR:-3600}"

die() { echo "error: $*" >&2; exit 2; }
command -v openssl >/dev/null || die "openssl not found"
command -v jq >/dev/null || die "jq not found"

now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# "2027-02-20 12:00:00Z" -> "2027-02-20T12:00:00Z"
iso() { sed -e 's/ /T/' -e 's/Z\{0,1\}$/Z/'; }

uuid() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then cat /proc/sys/kernel/random/uuid
  else openssl rand -hex 16; fi
}

# Print certificate-info JSON for one PEM certificate on stdin.
cert_info() {
  local pem; pem="$(cat)"
  local sha subj issuer serial nb na alg bits sig sans
  sha="$(openssl x509 -noout -fingerprint -sha256 <<<"$pem" | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
  subj="$(openssl x509 -noout -subject -nameopt RFC2253 <<<"$pem" | sed 's/^subject=//')"
  issuer="$(openssl x509 -noout -issuer -nameopt RFC2253 <<<"$pem" | sed 's/^issuer=//')"
  serial="$(openssl x509 -noout -serial <<<"$pem" | cut -d= -f2 | tr 'A-F' 'a-f' | sed 's/^0*//')"
  nb="$(openssl x509 -noout -startdate -dateopt iso_8601 <<<"$pem" | cut -d= -f2 | iso)"
  na="$(openssl x509 -noout -enddate -dateopt iso_8601 <<<"$pem" | cut -d= -f2 | iso)"
  alg="$(openssl x509 -noout -text <<<"$pem" | sed -n 's/^ *Public Key Algorithm: //p' | head -1)"
  bits="$(openssl x509 -noout -text <<<"$pem" | sed -n 's/^ *Public-Key: (\([0-9]*\) bit)/\1/p' | head -1)"
  sig="$(openssl x509 -noout -text <<<"$pem" | sed -n 's/^ *Signature Algorithm: //p' | head -1)"
  sans="$(openssl x509 -noout -ext subjectAltName <<<"$pem" 2>/dev/null \
          | tail -n +2 | tr ',' '\n' | sed -e 's/^ *//' -e 's/^[A-Za-z ]*://' | grep -v '^$' || true)"
  jq -n --arg sha "$sha" --arg subj "$subj" --arg issuer "$issuer" --arg serial "$serial" \
        --arg nb "$nb" --arg na "$na" --arg alg "$alg" --arg bits "$bits" --arg sig "$sig" \
        --arg sans "$sans" '
    {sha256:$sha, "subject-dn":$subj}
    + (if $sans == "" then {} else {san: ($sans | split("\n"))} end)
    + {"issuer-dn":$issuer, serial:$serial, "not-before":$nb, "not-after":$na,
       "public-key-algorithm":$alg}
    + (if $bits == "" then {} else {"public-key-size": ($bits|tonumber)} end)
    + {"signature-algorithm":$sig}'
}

# Status values computed locally (expired / not-yet-valid).
validity_status() {
  local pem="$1"
  if ! openssl x509 -noout -checkend 0 <<<"$pem" >/dev/null; then echo expired; fi
}

record() { # evidence subject_json location_json cert_json chain_json status_lines
  jq -n --arg rep "$REPORTER" --arg ev "$1" --argjson subj "$2" --argjson loc "$3" \
        --argjson cert "$4" --argjson chain "$5" --arg status "$6" \
        --arg at "$(now_utc)" --arg id "$(uuid)" --argjson vf "$VALID_FOR" '
    {version:1, "record-id":$id, reporter:$rep, subject:$subj, location:$loc,
     evidence:$ev, "observed-at":$at, "valid-for":$vf}
    + (if $cert == null then {} else {certificate:$cert} end)
    + (if $chain == null then {} else {chain:$chain} end)
    + (if $status == "" then {} else {status: ($status | split("\n") | map(select(. != "")) | unique)} end)'
}

# SHA-256 fingerprints of the 2nd..nth certificates in s_client -showcerts output.
chain_fingerprints() {
  local dir; dir="$(mktemp -d)"
  awk -v d="$dir" '/-----BEGIN CERTIFICATE-----/{n++; f=sprintf("%s/%03d.pem", d, n)}
                   n>=2 && f {print > f} /-----END CERTIFICATE-----/{f=""}'
  local p
  for p in "$dir"/*.pem; do
    [[ -s "$p" ]] || continue
    openssl x509 -noout -fingerprint -sha256 -in "$p" | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
  done
  rm -rf "$dir"
}

observe_wire() {
  local target host port out pem chain_fps status verify
  for target in "$@"; do
    host="${target%:*}"; port="${target##*:}"
    [[ "$host" == "$target" ]] && port=443
    out="$(timeout 15 openssl s_client -connect "$host:$port" -servername "$host" \
             -verify_return_error -verify_hostname "$host" -showcerts </dev/null 2>&1 || true)"
    pem="$(awk '/-----BEGIN CERTIFICATE-----/{c++} c==1' <<<"$out" | sed '/-----END CERTIFICATE-----/q')"
    if [[ -z "$pem" ]]; then
      # retry without verification to capture the certificate anyway
      out="$(timeout 15 openssl s_client -connect "$host:$port" -servername "$host" -showcerts </dev/null 2>&1 || true)"
      pem="$(awk '/-----BEGIN CERTIFICATE-----/{c++} c==1' <<<"$out" | sed '/-----END CERTIFICATE-----/q')"
    fi
    local subj loc
    subj="$(jq -n --arg h "$host" '{host:$h}')"
    loc="$(jq -n --arg s "$host" --argjson p "$port" '{port:$p, sni:$s}')"
    if [[ -z "$pem" ]]; then
      echo "warning: $target: no certificate received" >&2
      record observed-wire "$subj" "$loc" null null "not-found"
      continue
    fi
    status="$(validity_status "$pem")"
    if grep -q "Verify return code: 0 (ok)" <<<"$out"; then verify=valid
    else
      verify=invalid
      if grep -qi "hostname mismatch" <<<"$out"; then status+=$'\n'name-mismatch
      else status+=$'\n'chain-invalid; fi
    fi
    chain_fps="$(chain_fingerprints <<<"$out")"
    local chain
    chain="$(jq -n --arg v "$verify" --arg fps "$chain_fps" \
      '{validation:$v} + (if $fps == "" then {} else {certificates: ($fps | split("\n") | map(select(test("^[0-9a-f]{64}$"))))} end)')"
    record observed-wire "$subj" "$loc" "$(cert_info <<<"$pem")" "$chain" "$status"
  done
}

observe_store() {
  local f pem subj loc
  subj="$(jq -n --arg h "$REPORTER" '{host:$h}')"
  for f in "$@"; do
    [[ -f "$f" ]] || { echo "warning: $f: not a file" >&2; continue; }
    pem="$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/{p;/-----END CERTIFICATE-----/q}' "$f")"
    [[ -n "$pem" ]] || pem="$(openssl x509 -inform DER -in "$f" 2>/dev/null || true)"
    [[ -n "$pem" ]] || { echo "warning: $f: no certificate" >&2; continue; }
    loc="$(jq -n --arg p "$(realpath "$f")" '{path:$p}')"
    record observed-store "$subj" "$loc" "$(cert_info <<<"$pem")" '{"validation":"not-checked"}' "$(validity_status "$pem")"
  done
}

[[ $# -ge 2 ]] || { sed -n '2,15p' "$0"; exit 2; }
mode="$1"; shift
case "$mode" in
  wire)  records="$(observe_wire "$@")" ;;
  store) records="$(observe_store "$@")" ;;
  *) die "unknown mode: $mode" ;;
esac
[[ -n "$records" ]] || die "no records produced"

set_json="$(jq -s '{version:1, records:.}' <<<"$records")"
printf '%s\n' "$set_json"

if [[ -n "${COR_OUT:-}" ]]; then
  tmp="$(mktemp "$(dirname "$COR_OUT")/.cor-XXXXXX")"
  printf '%s\n' "$set_json" >"$tmp" && chmod 640 "$tmp" && mv -f "$tmp" "$COR_OUT"
fi
if [[ -n "${COR_PUSH_URL:-}" ]]; then
  curl -fsS -X POST -H "Content-Type: $MEDIA_TYPE" \
       ${COR_TOKEN:+-H "Authorization: Bearer $COR_TOKEN"} \
       --data-binary "$set_json" "$COR_PUSH_URL" >/dev/null
  echo "pushed to $COR_PUSH_URL" >&2
fi
