# mail-dns

A Claude Code skill for setting up, auditing, and repairing email authentication DNS (MX, SPF, DKIM, DMARC) on the common small-shop stack: **Cloudflare** holds DNS, **cPanel** sends and receives mail, and Exim signs outbound with the `default` DKIM selector.

The work is almost never "generate keys." It is "publish exactly what the server already expects, and prove it verifies." These scripts ask the server what it signs with, write the difference to Cloudflare, and read the result back from the authoritative nameserver so a record that was never saved never gets mistaken for one still propagating.

**Owner line:** your email can look perfectly configured in the dashboard and still land in spam. This checks the chain end to end, with a real test message, so "it's set up" means Gmail actually says `dkim=pass`.

## What's in here

| File | What it does |
|---|---|
| `SKILL.md` | The skill itself: the four-phase workflow, hard rules, symptom-to-cause table, and a field-tested Cloudflare dashboard fallback for zones a house API token can't reach. |
| `scripts/audit.sh` | Reads MX, SPF, DKIM, DMARC against the zone's authoritative nameservers and public resolvers. |
| `scripts/cpanel-expected.sh` | Asks the cPanel server over SSH for the exact DKIM record name and value it signs with, plus its mail routing. The only acceptable source for a DKIM key. |
| `scripts/cf-dns.sh` | Lists and upserts Cloudflare DNS records through the API, with a dry run and per-family replace so SPF never lands on top of a site-verification token. |

## The four phases

Run them in order. Each gate passes before the next starts.

```sh
# 1. Audit what is published
scripts/audit.sh <domain> [selector]

# 2. Ask the server what it expects
scripts/cpanel-expected.sh <ssh-alias> <domain>

# 3. Write the difference (dry run, then --yes)
scripts/cf-dns.sh upsert <zone> <name> <type> '<content>'
scripts/cf-dns.sh upsert <zone> <name> <type> '<content>' --yes

# 4. Prove it end to end: send a real message, read Authentication-Results,
#    require dkim=pass, spf=pass, dmarc=pass before tightening DMARC.
```

`SKILL.md` carries the full workflow, including the split-setup case (inbound MX at another provider), the Laravel `config:cache` gotcha, and the `p=none` → `quarantine` → `reject` ramp.

## Setup

A Cloudflare API token scoped **Zone > DNS > Edit**, read from one of:

```sh
export CLOUDFLARE_DNS_TOKEN=...            # this shell only
# or
printf %s '<token>' > ~/.config/cloudflare/dns-token && chmod 600 ~/.config/cloudflare/dns-token
```

Create one at Cloudflare → My Profile → API Tokens. No token is stored in this repo, and the scripts never echo one. Client domains usually live in the client's own Cloudflare account, which a house token can't reach. `cf-dns.sh list <zone>` tells you that up front so you can plan for the dashboard fallback.

`cpanel-expected.sh` needs an SSH alias for the cPanel box (check `~/.ssh/config`). `dig` is required for the audit.

## Install as a Claude Code skill

```sh
git clone <this-repo> ~/.claude/skills/mail-dns
```

Then invoke it in Claude Code as `/mail-dns <domain>`.

## Dependencies

`dig`, `curl`, `python3`, and `ssh`. On macOS: `brew install bind` for `dig`.
