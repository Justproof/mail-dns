#!/bin/bash
# Read and write Cloudflare DNS records through the API.
#
# Writes are DRY RUN unless you pass --yes. Nothing here touches a browser:
# the dashboard's edit form is where the 255-char truncation and stray-quote
# bugs come from, because it shows a long TXT value in a small box.
#
# Token, in order of preference:
#   $CLOUDFLARE_DNS_TOKEN
#   ~/.config/cloudflare/dns-token   (chmod 600)
# Scope it to Zone > DNS > Edit for the zones you manage. Never paste a token
# into a chat, a commit, or a shell history line.
#
# Usage:
#   cf-dns.sh list   <zone> [name-substring]
#   cf-dns.sh get    <zone> <name> <type>
#   cf-dns.sh upsert <zone> <name> <type> <content> [--yes]
#   cf-dns.sh delete <zone> <name> <type> [content-prefix] [--yes]
#
# A name can hold several TXT records. upsert targets the one in the same
# family (v=spf1 replaces v=spf1, never the site-verification token beside it);
# delete refuses to guess and asks for a content-prefix.

set -uo pipefail

API="https://api.cloudflare.com/client/v4"

TOKEN="${CLOUDFLARE_DNS_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -r "$HOME/.config/cloudflare/dns-token" ]; then
  TOKEN=$(tr -d '[:space:]' < "$HOME/.config/cloudflare/dns-token")
fi
if [ -z "$TOKEN" ]; then
  cat >&2 <<'EOF'
No Cloudflare token found.

  export CLOUDFLARE_DNS_TOKEN=...          (this shell only)
  or
  mkdir -p ~/.config/cloudflare
  printf %s '<token>' > ~/.config/cloudflare/dns-token
  chmod 600 ~/.config/cloudflare/dns-token

Create one at Cloudflare > My Profile > API Tokens, scoped Zone > DNS > Edit.
EOF
  exit 2
fi

cf() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$method" "$API$path" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      --data "$body"
  else
    curl -sS -X "$method" "$API$path" -H "Authorization: Bearer $TOKEN"
  fi
}

# Fail loudly on API errors instead of silently returning nothing.
check() {
  python3 -c '
import sys, json
d = json.load(sys.stdin)
if not d.get("success"):
    for e in d.get("errors", []):
        print("cloudflare error", e.get("code"), e.get("message"), file=sys.stderr)
    sys.exit(1)
json.dump(d, sys.stdout)
'
}

zone_id() {
  cf GET "/zones?name=$1" | check | python3 -c '
import sys, json
r = json.load(sys.stdin).get("result") or []
if not r:
    print("zone not found; is it on this account and does the token cover it?", file=sys.stderr)
    print("Client zones often live in the client'"'"'s own Cloudflare account. Either add the zone", file=sys.stderr)
    print("to the token, or use the dashboard fallback in SKILL.md (phase 3).", file=sys.stderr)
    sys.exit(1)
print(r[0]["id"])
'
}

record_json() { # zone_id name type -> id and content, tab separated
  cf GET "/zones/$1/dns_records?name=$2&type=$3" | check | python3 -c '
import sys, json
for r in (json.load(sys.stdin).get("result") or []):
    print(r["id"] + "\t" + r["content"])
'
}

# Choose WHICH existing record an operation targets. A name can hold several
# records of one type (apex TXT: SPF next to site-verification tokens), so
# "first match by name+type" can overwrite the wrong one.
#   TXT upsert: match by family (v=spf1, v=DKIM1, v=DMARC1, or the key before "=")
#   other upsert: exact content match, else the sole record, else refuse
#   delete: sole record, or the one whose content starts with <match>
# stdin: "id<TAB>content" lines. stdout: chosen line, or nothing (= create).
# Exit 3 when ambiguous.
pick() { # mode type needle
  python3 -c '
import sys, re
mode, typ, needle = sys.argv[1], sys.argv[2], sys.argv[3]
def norm(s):
    return s.replace("\" \"", "").replace("\"", "").strip()
def family(s):
    s = norm(s)
    # Letters then digits, so a glued "v=spf1include:..." still lands in family v=spf1
    # and gets replaced, rather than a second SPF record being created beside it.
    m = re.match(r"(v=[A-Za-z]+[0-9]+)", s)
    if m:
        return m.group(1).lower()
    if "=" in s:
        return s.split("=", 1)[0].lower() + "="
    return s.lower()
rows = [l.rstrip("\n").split("\t", 1) for l in sys.stdin if l.strip()]
rows = [r for r in rows if len(r) == 2]
if mode == "upsert":
    if typ == "TXT":
        cands = [r for r in rows if family(r[1]) == family(needle)]
    else:
        want = norm(needle).split()[-1].rstrip(".").lower()
        exact = [r for r in rows if norm(r[1]).rstrip(".").lower() == want]
        cands = exact or rows
else:
    cands = [r for r in rows if norm(r[1]).startswith(needle)] if needle else rows
if len(cands) > 1:
    print(f"Refusing: {len(cands)} {typ} records match and I will not guess which:", file=sys.stderr)
    for r in cands:
        print(f"  {norm(r[1])[:90]}", file=sys.stderr)
    sys.exit(3)
if cands:
    print("\t".join(cands[0]))
' "$1" "$2" "$3"
}

CMD="${1:-}"; shift 2>/dev/null

case "$CMD" in
  list)
    ZONE="${1:-}"; FILTER="${2:-}"
    [ -z "$ZONE" ] && { echo "usage: cf-dns.sh list <zone> [name-substring]" >&2; exit 2; }
    ZID=$(zone_id "$ZONE") || exit 1
    cf GET "/zones/$ZID/dns_records?per_page=200" | check | python3 -c '
import sys, json
flt = sys.argv[1] if len(sys.argv) > 1 else ""
rows = json.load(sys.stdin).get("result") or []
rows.sort(key=lambda r: (r["type"], r["name"]))
for r in rows:
    if flt and flt not in r["name"]:
        continue
    content = r["content"]
    if len(content) > 70:
        content = content[:67] + "..."
    print("%-6s %-42s %s" % (r["type"], r["name"], content))
' "$FILTER"
    ;;

  get)
    ZONE="${1:-}"; NAME="${2:-}"; TYPE="${3:-}"
    [ -z "$TYPE" ] && { echo "usage: cf-dns.sh get <zone> <name> <type>" >&2; exit 2; }
    ZID=$(zone_id "$ZONE") || exit 1
    record_json "$ZID" "$NAME" "$TYPE" | cut -f2
    ;;

  upsert)
    ZONE="${1:-}"; NAME="${2:-}"; TYPE="${3:-}"; CONTENT="${4:-}"; CONFIRM="${5:-}"
    [ -z "$CONTENT" ] && { echo "usage: cf-dns.sh upsert <zone> <name> <type> <content> [--yes]" >&2; exit 2; }

    # Guard the exact bug that cost an afternoon: zone-file quotes are
    # delimiters, not content, and they break DKIM silently.
    case "$CONTENT" in
      '"'*) echo "Refusing: content starts with a quote. Strip surrounding quotes; they are zone-file syntax." >&2; exit 1 ;;
    esac
    case "$CONTENT" in
      *'v=DKIM1'*)
        P=$(printf '%s' "$CONTENT" | sed -n 's/.*p=\([A-Za-z0-9+\/=]*\).*/\1/p')
        case "$P" in
          *IDAQAB) : ;;
          *) echo "Refusing: DKIM key does not end in IDAQAB, so it is truncated (len ${#P})." >&2; exit 1 ;;
        esac
        ;;
    esac

    ZID=$(zone_id "$ZONE") || exit 1
    EXISTING=$(record_json "$ZID" "$NAME" "$TYPE" | pick upsert "$TYPE" "$CONTENT") || exit 1
    RID=$(printf '%s' "$EXISTING" | cut -f1)
    # The API returns TXT as quoted 255-char chunks; unwrap so the diff compares like with like.
    OLD=$(printf '%s' "$EXISTING" | cut -f2 | sed 's/" "//g' | tr -d '"')

    # MX content is given as "10 host"; the API wants priority as its own field.
    BODY=$(python3 -c '
import json, sys, re
typ, name, content = sys.argv[1], sys.argv[2], sys.argv[3]
body = {"type": typ, "name": name, "content": content, "ttl": 1}
m = re.match(r"^(\d+)\s+(\S+)$", content)
if typ == "MX" and m:
    body["priority"] = int(m.group(1))
    body["content"] = m.group(2).rstrip(".")
print(json.dumps(body))
' "$TYPE" "$NAME" "$CONTENT")

    if [ -n "$RID" ] && [ "$OLD" = "$CONTENT" ]; then
      echo "UNCHANGED $TYPE $NAME (already matches)"
      exit 0
    fi

    if [ -n "$RID" ]; then
      echo "UPDATE $TYPE $NAME"
      echo "  from: $OLD"
      echo "  to:   $CONTENT"
    else
      echo "CREATE $TYPE $NAME"
      echo "  to:   $CONTENT"
    fi

    if [ "$CONFIRM" != "--yes" ]; then
      echo
      echo "Dry run. Re-run with --yes to apply."
      exit 0
    fi

    if [ -n "$RID" ]; then
      cf PUT "/zones/$ZID/dns_records/$RID" "$BODY" | check >/dev/null && echo "updated"
    else
      cf POST "/zones/$ZID/dns_records" "$BODY" | check >/dev/null && echo "created"
    fi
    ;;

  delete)
    ZONE="${1:-}"; NAME="${2:-}"; TYPE="${3:-}"; MATCH=""; CONFIRM=""
    [ -z "$TYPE" ] && { echo "usage: cf-dns.sh delete <zone> <name> <type> [content-prefix] [--yes]" >&2; exit 2; }
    for arg in "${4:-}" "${5:-}"; do
      case "$arg" in --yes) CONFIRM="--yes" ;; ?*) MATCH="$arg" ;; esac
    done
    ZID=$(zone_id "$ZONE") || exit 1
    TARGET=$(record_json "$ZID" "$NAME" "$TYPE" | pick delete "$TYPE" "$MATCH") || exit 1
    RID=$(printf '%s' "$TARGET" | cut -f1)
    [ -z "$RID" ] && { echo "no matching $TYPE record named $NAME" >&2; exit 1; }
    echo "DELETE $TYPE $NAME"
    echo "  was:  $(printf '%s' "$TARGET" | cut -f2)"
    [ "$CONFIRM" != "--yes" ] && { echo "Dry run. Re-run with --yes to apply."; exit 0; }
    cf DELETE "/zones/$ZID/dns_records/$RID" | check >/dev/null && echo "deleted"
    ;;

  *)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
