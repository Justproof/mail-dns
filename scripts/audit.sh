#!/bin/bash
# Audit published email-auth DNS for a domain: MX, SPF, DKIM, DMARC.
# Queries the zone's authoritative nameservers AND public resolvers, because
# "not saved" and "not propagated" look identical from a public resolver alone.
#
# Usage: audit.sh <domain> [selector]     (selector defaults to "default", cPanel's)
# Exit:  0 = all checks pass, 1 = at least one FAIL, 2 = usage error

set -uo pipefail

DOMAIN="${1:-}"
SELECTOR="${2:-default}"
[ -z "$DOMAIN" ] && { echo "usage: audit.sh <domain> [selector]" >&2; exit 2; }

FAILED=0
pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=1; }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$1"; }
info() { printf '        %s\n' "$1"; }

# Join the 255-char strings dig prints as "chunk1" "chunk2" and drop the quotes.
# A TXT record over 255 chars is ALWAYS split; joining with anything between
# them (space, newline) corrupts a DKIM key silently.
join_txt() { printf '%s' "$1" | sed 's/" "//g' | tr -d '"'; }

AUTH_NS=$(dig +short NS "$DOMAIN" | head -1)
[ -z "$AUTH_NS" ] && { echo "No NS records for $DOMAIN. Is the domain registered and delegated?" >&2; exit 1; }

echo
echo "=== $DOMAIN (selector: $SELECTOR) ==="
echo "authoritative: $AUTH_NS"
echo

# ---------------------------------------------------------------- MX
echo "MX"
MX=$(dig +short MX "$DOMAIN" @"$AUTH_NS" | sort -n)
if [ -z "$MX" ]; then
  fail "no MX record; the domain cannot receive mail"
else
  echo "$MX" | while read -r line; do info "$line"; done
  MX_HOST=$(echo "$MX" | head -1 | awk '{print $2}' | sed 's/\.$//')
  if [ -n "$(dig +short A "$MX_HOST")" ]; then
    pass "MX host resolves"
  else
    fail "MX host $MX_HOST does not resolve"
  fi
fi
echo

# ---------------------------------------------------------------- SPF
echo "SPF"
SPF=$(dig +short TXT "$DOMAIN" @"$AUTH_NS" | grep 'v=spf1' | head -1)
if [ -z "$SPF" ]; then
  fail "no SPF record"
else
  SPF_CLEAN=$(join_txt "$SPF")
  info "$SPF_CLEAN"
  SPF_N=$(dig +short TXT "$DOMAIN" @"$AUTH_NS" | grep -c 'v=spf1')
  [ "$SPF_N" -gt 1 ] && fail "$SPF_N SPF records at the apex; more than one is a permerror"
  # Glued tokens ("v=spf1include:x~all") parse as one unknown term: permerror, so
  # the record protects nothing, and the checks below misreport it as a dead include.
  case "$SPF_CLEAN" in
    'v=spf1 '*|'v=spf1') : ;;
    *) fail "malformed: 'v=spf1' must be followed by a space; receivers treat this record as permerror" ;;
  esac
  echo "$SPF_CLEAN" | grep -qE '[^ ][-~?+]all$' && fail "malformed: the 'all' mechanism is glued to the previous term"
  # Count lookups through the whole include tree; the limit of 10 is recursive,
  # and one host include (spf.web-hosting.com) alone costs 7.
  COUNT=$(python3 - "$DOMAIN" <<'PY'
import subprocess, sys, re
seen = set()
def txt(name):
    out = subprocess.run(["dig", "+short", "TXT", name], capture_output=True, text=True).stdout
    for line in out.splitlines():
        rec = line.replace('" "', "").replace('"', "")
        if rec.startswith("v=spf1"):
            return rec
    return ""
def count(name, depth=0):
    if depth > 10 or name in seen:
        return 0
    seen.add(name)
    n = 0
    for term in txt(name).split()[1:]:
        term = term.lstrip("+-~?").lower()
        m = re.match(r"(include:|redirect=)(\S+)", term)
        if m:
            n += 1 + count(m.group(2), depth + 1)
        elif re.match(r"(a|mx|ptr)([:/]|$)|exists:", term):
            n += 1
    return n
print(count(sys.argv[1]))
PY
)
  if [ "$COUNT" -gt 10 ]; then
    fail "$COUNT DNS lookups across the include tree; SPF hard-caps at 10 and fails permerror past it"
  else
    pass "$COUNT DNS lookups across the include tree (limit 10)"
  fi
  case "$SPF_CLEAN" in
    *' -all'*) pass "hard fail (-all)" ;;
    *' ~all'*) pass "soft fail (~all)" ;;
    *' ?all'*) warn "neutral (?all) authorizes nothing in practice" ;;
    *) warn "no all mechanism; SPF is effectively neutral" ;;
  esac
  echo "$SPF_CLEAN" | grep -o 'include:[^ ]*' | while read -r inc; do
    host=${inc#include:}
    [ -z "$(dig +short TXT "$host")" ] && warn "include $host returns no SPF record (dead include)"
  done
fi
echo

# ---------------------------------------------------------------- DKIM
echo "DKIM  ($SELECTOR._domainkey.$DOMAIN)"
RAW=$(dig +short TXT "$SELECTOR._domainkey.$DOMAIN" @"$AUTH_NS")
if [ -z "$RAW" ]; then
  fail "no DKIM record at this selector"
  for alt in default dkim mail google selector1 selector2 sig1 fm1 k1 s1 mandrill; do
    [ "$alt" = "$SELECTOR" ] && continue
    if [ -n "$(dig +short TXT "$alt._domainkey.$DOMAIN" @"$AUTH_NS")" ]; then
      warn "but a record EXISTS at selector '$alt' - wrong name, or a different provider signs this domain"
    fi
  done
else
  # A literal quote inside the record shows up as \" in dig's output.
  case "$RAW" in *'\"'*) fail "record contains literal quote characters; quotes are zone-file delimiters, not content" ;; esac

  VALUE=$(join_txt "$RAW")
  P=$(printf '%s' "$VALUE" | sed -n 's/.*p=\([A-Za-z0-9+/=]*\).*/\1/p')

  if [ -z "$P" ]; then
    fail "no p= public key in the record"
  else
    LEN=${#P}
    info "p= length: $LEN"
    PEM=$(mktemp)
    { echo "-----BEGIN PUBLIC KEY-----"; printf '%s\n' "$P" | fold -w 64; echo "-----END PUBLIC KEY-----"; } > "$PEM"
    BITS=$(openssl pkey -pubin -in "$PEM" -noout -text 2>/dev/null | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p')
    rm -f "$PEM"
    if [ -n "$BITS" ]; then
      pass "valid RSA public key ($BITS bit)"
      [ "$BITS" -lt 1024 ] && warn "keys under 1024 bit are rejected by major receivers"
    else
      fail "key does not parse as RSA"
      # 2048-bit = exactly 392 base64 chars ending IDAQAB. 1024-bit = 216.
      case "$LEN" in
        216|392) info "length is right, so the bytes are wrong: a mistyped character, not truncation" ;;
        *) info "expected 392 chars for 2048-bit (or 216 for 1024-bit)" ;;
      esac
      case "$P" in
        *IDAQAB) : ;;
        *) info "key does not end in IDAQAB, so it is TRUNCATED - the second 255-char chunk is missing" ;;
      esac
    fi
  fi
fi
echo

# ---------------------------------------------------------------- DMARC
echo "DMARC (_dmarc.$DOMAIN)"
DMARC=$(join_txt "$(dig +short TXT "_dmarc.$DOMAIN" @"$AUTH_NS" | head -1)")
if [ -z "$DMARC" ]; then
  fail "no DMARC record"
else
  info "$DMARC"
  case "$DMARC" in
    *p=reject*)     pass "p=reject (strictest)" ;;
    *p=quarantine*) pass "p=quarantine (enforcing)" ;;
    *p=none*)       warn "p=none only reports; it does not protect the domain" ;;
    *)              fail "no p= policy tag" ;;
  esac
  case "$DMARC" in
    *rua=*) pass "aggregate reports configured" ;;
    *) warn "no rua= address, so you will never see who is sending as this domain" ;;
  esac
fi
echo

# ------------------------------------------------- propagation cross-check
echo "PROPAGATION"
# A name can hold several TXT records (SPF alongside site-verification tokens),
# and resolvers return them in any order, so sort before comparing.
fingerprint() { dig +short TXT "$1" @"$2" | sed 's/" "//g' | tr -d '"' | sort | shasum | cut -d' ' -f1; }

for rec in "$DOMAIN:TXT" "$SELECTOR._domainkey.$DOMAIN:TXT" "_dmarc.$DOMAIN:TXT"; do
  name=${rec%:*}
  a=$(fingerprint "$name" "$AUTH_NS")
  b=$(fingerprint "$name" 1.1.1.1)
  if [ "$a" = "$b" ]; then
    pass "$name matches on authoritative and public resolvers"
  else
    warn "$name differs between authoritative and 1.1.1.1 (still propagating, or cached)"
  fi
done
echo

[ "$FAILED" -eq 0 ] && echo "All checks passed." || echo "One or more checks FAILED (see above)."
exit "$FAILED"
