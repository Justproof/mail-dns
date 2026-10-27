#!/bin/bash
# Ask the cPanel server what email-auth DNS it expects for a domain.
#
# This is the authoritative source for the DKIM public key. The server holds the
# private key, so whatever it names here is what will actually verify. Never
# transcribe a key from a screenshot or a control panel when this call exists.
#
# Usage: cpanel-expected.sh <ssh-alias> <domain> [--copy-dkim]
# Exit:  0 ok, 1 ssh/API failure, 2 usage

set -uo pipefail

ALIAS="${1:-}"
DOMAIN="${2:-}"
[ -z "$ALIAS" ] || [ -z "$DOMAIN" ] && { echo "usage: cpanel-expected.sh <ssh-alias> <domain> [--copy-dkim]" >&2; exit 2; }

run_uapi() {
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$ALIAS" \
    "uapi --output=json EmailAuth $1 domain=$DOMAIN" 2>/dev/null
}

parse() {
  python3 -c '
import sys, json
label = sys.argv[1]
try:
    payload = json.load(sys.stdin)
except Exception:
    print(f"{label}\terror\tcould not parse cPanel response")
    sys.exit(0)
res = payload.get("result") or {}
if not res.get("status"):
    errs = res.get("errors") or ["unknown error"]
    print(f"{label}\terror\t{errs[0]}")
    sys.exit(0)
for row in (res.get("data") or []):
    for key in ("domain", "subdomain", "expected", "record", "state"):
        if row.get(key) is not None:
            print(f"{label}\t{key}\t{row[key]}")
    for pub in (row.get("records") or []):
        cur = pub.get("current")
        if cur is not None:
            print(f"{label}\tcurrent\t{cur}")
' "$1"
}

echo "=== $DOMAIN, as cPanel on '$ALIAS' expects it ==="
echo

if ! ssh -o BatchMode=yes -o ConnectTimeout=15 "$ALIAS" true 2>/dev/null; then
  echo "Cannot reach '$ALIAS' over SSH with BatchMode (key auth)." >&2
  exit 1
fi

OUT=$(for pair in "validate_current_dkims:DKIM" "validate_current_spfs:SPF" "validate_current_dmarcs:DMARC"; do
  func=${pair%:*}
  label=${pair#*:}
  run_uapi "$func" | parse "$label"
done)
echo "$OUT"

# Mail routing. When MX points at another provider (IONOS, Google, M365), cPanel must
# be "remote", or mail the site sends to its own domain (lead notifications to the
# owner) is delivered into a local mailbox nobody reads.
ssh -o BatchMode=yes -o ConnectTimeout=15 "$ALIAS" \
  "uapi --output=json Email list_mxs domain=$DOMAIN" 2>/dev/null | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)["result"]["data"][0]
except Exception:
    print("ROUTING\terror\tcould not read Email list_mxs"); sys.exit(0)
mode = "local" if d.get("local") else "remote" if d.get("remote") else "backup" if d.get("secondary") else "?"
print("ROUTING\tmode\t%s (detected: %s, mxcheck: %s)" % (mode, d.get("detected"), d.get("mxcheck")))
'
MX=$(dig +short MX "$DOMAIN" | sort -n | head -1 | awk '{print $2}')
echo "ROUTING	public MX	${MX:-none}"

if [ "${3:-}" = "--copy-dkim" ]; then
  KEY=$(printf '%s\n' "$OUT" | awk -F'\t' '$1=="DKIM" && $2=="expected"{print $3; exit}')
  if [ -n "$KEY" ]; then
    printf '%s' "$KEY" | pbcopy
    echo
    echo "DKIM value copied to clipboard: ${#KEY} chars, sha256 $(printf '%s' "$KEY" | shasum -a 256 | cut -d' ' -f1)"
    echo "Re-run this right before pasting; anything else copied in between replaces it."
  else
    echo "No expected DKIM value to copy." >&2
  fi
fi

cat <<'NOTE'

Reading this:
  domain/subdomain  the exact record NAME to publish, selector included
  expected          what the server wants published
  current           what it sees published right now
  state             VALID means server and DNS already agree

SPF "expected" is a mechanism fragment, not a whole record. Wrap it, and keep the
include of any other provider that also sends as this domain (the MX host's, usually):
  v=spf1 <expected> [include:<other provider>] ~all

ROUTING must be "remote" when the public MX is not this server, "local" when it is.
NOTE
