---
name: mail-dns
description: Set up, audit, or repair email authentication DNS (MX, SPF, DKIM, DMARC) for a site on Cloudflare DNS + cPanel mail. Use when launching a new site's email, when mail lands in spam, when DKIM fails or shows permerror, when a DMARC report looks wrong, or when the user says "set up email for <domain>". Covers key verification, Cloudflare API writes (with a tested dashboard fallback for zones in a client's account), split setups where inbound MX is at another provider, app-side SMTP checks, end-to-end delivery testing, and the DMARC none-to-quarantine ramp.
---

# Mail DNS (Cloudflare + cPanel)

House setup: **Cloudflare** holds DNS, **cPanel** sends and receives mail. Exim on the
cPanel box signs outbound mail with DKIM selector `default` automatically. The work is
almost never "generate keys" — it is "publish exactly what the server already expects,
and prove it verifies."

Invoke as `/mail-dns <domain>`.

## What you need up front

- The domain.
- The SSH alias for its cPanel server (check `~/.ssh/config`). The mail server is usually
  the same box you deploy to.
- A Cloudflare API token scoped **Zone > DNS > Edit**. See `scripts/cf-dns.sh` header for
  where to put it. Never ask for a token in chat and never echo one.
- **Proof the token covers this zone:** `scripts/cf-dns.sh list <zone>` before anything
  else. Client domains usually sit in the *client's* Cloudflare account, which a house
  token does not reach. Finding that out at write time cost a detour; find it now and
  plan for the dashboard fallback (phase 3) if it fails.
- **Explicit go-ahead for the writes.** Auto mode blocks DNS changes as a category, and an
  instruction like "set up DNS" does not clear it. List the exact records (name, type,
  content) and get a yes before phase 3.
- **Where inbound mail lives.** If MX points elsewhere (IONOS, Google, M365) while the
  site sends through cPanel, this is a *split* setup: SPF must authorize both, and cPanel
  routing must be `remote` (phase 2 reports it).

## The four phases

Run them in order. Each gate must pass before moving on.

### 1. Audit what is published

```
scripts/audit.sh <domain> [selector]
```

Checks MX, SPF, DKIM, DMARC against the zone's **authoritative** nameservers and public
resolvers. The authoritative query is the important one: it distinguishes "never saved"
from "still propagating," which look identical from `1.1.1.1` and will otherwise cost you
twenty minutes of waiting for a record that was never there.

### 2. Ask the server what it expects

```
scripts/cpanel-expected.sh <ssh-alias> <domain>
```

This returns the exact record name (selector included) and the exact DKIM value the
server will sign with. **This is the only acceptable source for a DKIM key.**

It also prints `ROUTING`. With MX at another provider it must read `remote`; `local`
means mail the site sends to its own domain (lead notifications to the owner's
`@domain` address) lands in a cPanel mailbox nobody reads, while every DNS check passes.

SPF `expected` from cPanel is the *cPanel* half only. Keep the include of whoever else
sends as the domain (the MX provider's mailbox users send through it too), so
`v=spf1 ip4:<server> include:spf.web-hosting.com include:<mx provider spf> ~all`.

Add `--copy-dkim` to put the exact value on the clipboard with its length and SHA-256,
for the dashboard fallback.

### 3. Write the difference

```
scripts/cf-dns.sh upsert <zone> <name> <type> '<content>'          # dry run
scripts/cf-dns.sh upsert <zone> <name> <type> '<content>' --yes    # apply
```

Dry run first, show the diff, then apply. The script refuses content with leading quotes
or a truncated DKIM key, but those guards are a backstop, not a substitute for reading
the diff.

Prefer the API: the dashboard form is where truncation and stray quotes come from.
Browser automation is the fallback only when no token covers the zone.

#### Dashboard fallback (Claude in Chrome)

Field-tested on a client zone. Each step exists because skipping it failed once:

- **Use the forms, not the dashboard's own API.** Calling `/api/v4` from the page with
  the session's `x-atok` reads fine but every write returns a 403 bot-challenge page.
  Do not try to get past it; bot protection is a wall, not a puzzle.
- **One record per dialog, from a freshly loaded page.** After a failed save the
  Add record button stopped opening the dialog. Reload the DNS page; do not keep clicking.
- **Set Type first, then click into Name.** Typing `TXT` + Enter in the type picker can
  leave it focused, and the next text you type (the name) goes into its filter instead.
  Screenshot after selecting the type.
- **Real keystrokes, not `form_input`.** A programmatically set Name looked right in the
  DOM, but the form's state never saw it; Save closed the dialog and created nothing.
- **DKIM by clipboard, verified by hash.** Run `cpanel-expected.sh <alias> <domain>
  --copy-dkim` *immediately* before pasting (the clipboard was overwritten by a page URL
  between copy and paste once). Before Save, hash the field in the page:
  `crypto.subtle.digest('SHA-256', new TextEncoder().encode(textarea.value))` and compare
  with the script's digest. Save only on an exact match.
- **Read the dialog's sentence before Save.** "`<name>` has a record with content
  `<content>`" shows the fully qualified name and content as the form will submit them.
- **The record counter lies.** "9 of 200 records" did not update after saves. Verify
  with `dig @<authoritative ns>` and `cpanel-expected.sh` (state `VALID`), never the UI.
- The extension's privacy filter can blank JS readbacks that contain an email address
  (the DMARC `rua=`). Fall back to a screenshot of the field.

A name can hold several TXT records (the apex carries SPF beside site-verification
tokens). `upsert` replaces only the record in the same family, so `v=spf1` never lands on
top of `google-site-verification=`. `delete` refuses to guess: pass a content prefix.
If `upsert` reports two records in one family (two `v=spf1`), that is itself a bug in the
zone, since duplicate SPF is a permerror. Delete one by prefix, then upsert.

**After every write, re-run phase 1.** The write is not done until `audit.sh` reads the
record back from the authoritative nameserver and the key parses.

### 4. Prove it end to end

**First, prove the app actually uses SMTP.** On Laravel, a `.env` edit does nothing
while `bootstrap/cache/config.php` exists: today's app kept writing mail to the log for
an hour after SMTP settings were added. Run `php artisan config:cache`, then check the
login without sending anything:

```
ssh <alias> 'cd <app> && php artisan tinker --execute='"'"'$t = app("mail.manager")->mailer()->getSymfonyTransport(); $t->start(); echo get_class($t); $t->stop();'"'"''
```

`LogTransport::start()` undefined means the mailer is still `log`. Also check where the
app sends *to* (e.g. a lead-recipient env var); an empty recipient list fails silently.

DNS looking right is not the same as mail verifying. A test message is sending mail on
the user's behalf, so name the recipient and get a yes. Send through the real path:

```
ssh <alias> '/usr/sbin/sendmail -t -i -f <mailbox>@<domain>' <<'EOF'
From: <mailbox>@<domain>
To: <a gmail address you control>
Subject: DKIM test from <domain>

Body text.
EOF
```

Then read `Authentication-Results` on the delivered message (Gmail: Show original, or the
Gmail MCP tools with `messageFormat: RAW`). Require all three:

```
dkim=pass   header.i=@<domain> header.s=default
spf=pass
dmarc=pass
```

`dkim=permerror (no key for signature)` means the server is signing but DNS has no
matching key. That is the common broken state, and it is invisible until you read headers.

## Hard rules

1. **Never transcribe a DKIM key.** Not from a screenshot, not from a control panel, not
   from a zone-file export you are reading by eye. Get it from phase 2. If you somehow
   must verify a transcription, hash both copies and compare digests rather than reading
   character by character: `l`/`I` and `0`/`O` produce a key that parses fine and fails
   every signature.
2. **Never publish a record whose target does not resolve.** If a provider gives you a
   CNAME target, `dig` it first. Providers only create the target once the domain is
   provisioned on their side, and a dangling DKIM selector is worse than a missing one.
3. **Never tighten DMARC before a confirmed pass.** Order is always: publish DKIM, prove
   `dkim=pass` with a real message, *then* raise the policy. Reversing it spam-folders
   the site's own transactional mail, and nobody notices for weeks.
4. **SPF should describe reality.** Remove includes for services the domain does not
   actually send through. Every include is a lookup against the limit of 10 and a standing
   authorization you are not watching.
5. **Add the sender before the send.** New newsletter tool, transactional API, or CRM? It
   needs an SPF entry or its own DKIM selector *before* its first send, or an enforcing
   policy quarantines it.

## Symptom to cause

| Symptom | Cause | Fix |
|---|---|---|
| `dkim=permerror (no key for signature)` | server signs, DNS has no key at that selector | publish phase 2's value |
| Key parses but is short of 392 chars, no `IDAQAB` ending | only the first 255-char chunk was pasted | join both chunks with nothing between them |
| Key is 392 chars but will not parse | a character was misread | re-pull from phase 2 |
| Record exists but nothing resolves | saved under the wrong name | cPanel signs as `default`, not `dkim` |
| `dig` shows `\"` inside the record | zone-file quotes pasted as content | strip them; quotes are delimiters. (Cloudflare now *displays* TXT content wrapped in quotes; that alone is normal.) |
| Authoritative has it, `1.1.1.1` does not | genuine propagation | wait; TTL on Cloudflare "Auto" is short |
| Neither has it | never saved | the dashboard form silently discards unsaved edits, and closes the dialog anyway |
| `spf=pass` from an unexpected IP | host relays outbound through a filter | normal; it is covered by the host's include |
| SPF like `v=spf1include:x~all`; audit says "malformed" | spaces lost when someone retyped it | rewrite it; until then it is permerror and protects nothing, even the provider it names |
| Two `v=spf1` records after a fix | old upsert treated the glued record as a different family | fixed in `cf-dns.sh`; delete the stale one by prefix |
| Audit passes, cPanel `VALID`, app sends nothing | Laravel config cache predates the `.env` edit | `php artisan config:cache`, then the phase 4 transport check |
| Site mail to the owner's own `@domain` never arrives | cPanel routing `local` while MX is elsewhere | set Email Routing to Remote in cPanel |
| Old third-party `*._domainkey` CNAME resolves to nothing | provider deprovisioned that selector | harmless but dangling; delete after confirming the provider no longer signs with it |

## Selector reference

Only `default` matters for the house setup, but if a domain adds a sender:

| Provider | Record | Name |
|---|---|---|
| cPanel / Exim | TXT | `default._domainkey` |
| Google Workspace | TXT | `google._domainkey` |
| Microsoft 365 | CNAME | `selector1._domainkey`, `selector2._domainkey` |
| iCloud+ | CNAME | `sig1._domainkey` |
| Fastmail | CNAME | `fm1`–`fm3._domainkey` |

A 2048-bit key is exactly **392** base64 characters ending `IDAQAB`. A 1024-bit key is
**216**. Any other length on an RSA key means truncation.

## DMARC ramp

Start `p=none` with a `rua=` address on a mailbox someone reads. Once reports show every
legitimate sender passing (give it a week of real traffic), move to `p=quarantine`, then
`p=reject`. Never skip the reporting period on a domain that already sends mail: the
reports are the only way to discover the sender you forgot about.
