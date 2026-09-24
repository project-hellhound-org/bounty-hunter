---
name: 403-bypass
description: Methodology for bypassing a 403/401 on a path you can't otherwise reach — header spoofing, path manipulation, method override, and origin/internal-trust tricks. Use when a discovered endpoint (admin panel, internal API, staff route) returns 403/401 and you have no valid credentials for it, or want to confirm a reverse-proxy/access-control misconfiguration.
---

# 403/401 FORBIDDEN BYPASS METHODOLOGY

This applies when you've found a path that clearly exists (a 403/401, not a
404) but you can't access it — no valid session, or a session that's
correctly rejected. The goal is to find a way the *server* (or a proxy in
front of it) can be tricked into treating your request as authorized or
internal, without ever obtaining real credentials.

This is a real, recurring bug class, not a theoretical one — disclosed
reports across many programs confirm the exact techniques below actually
work in production: Acronis paid out for `X-Forwarded-For: 127.0.0.1`
unlocking an nginx status endpoint (HackerOne #1224089); Yelp's Business
Owner App backend API was reachable the same way via `X-Forward-For:
127.0.0.1` (#1011767); a Kubernetes ingress auth bypass came from
manipulating `X-Original-Url`/`X-Auth-Request-Redirect` via a `../`-laced
request so an external auth service returned 204 instead of 401/403
(#1357948); and MacKeeper's `/admin` was reachable past its front nginx
by sending `X-Rewrite-Url`/`X-Original-Url` — headers the front proxy
ignored but the backend honored (#737323). None of this is exotic —
it's the same handful of trust-boundary mistakes recurring across
completely different stacks. For more recent examples specific to the
target's industry, `hackerone_search` (keyword: "403 bypass", "forbidden
bypass", or the specific header/technique you're considering) pulls live
disclosed reports — worth a quick check before assuming a technique is
stale or too well-known to still work.

## 0. Running the Battery (use the tool, don't hand-type every curl)

The `403_bypass` tool runs the bundled payload battery for you —
header spoofing, protocol/port tricks, method override, URL encoding, and
a WAF/SQLi-bypass mode — against a single URL in one call, instead of you
constructing each curl by hand. Call it with `mode: "exploit"` for the
full battery, or narrow to one category (`header`, `protocol`, `port`,
`httpmethod`, `encode`, `sqli`) once you have a specific reason to suspect
that one. It returns every payload that came back with a *different*
status code than the original 403/401 — as `candidates_2xx`, each with a
`curl_repro` you can re-run yourself.

**The tool's output is a lead list, not a findings list — nothing in
`candidates_2xx` is confirmed.** This is exactly the same caveat the
public `forbidden` bypass tool (ivan-sincek) ships with: it's
brute-force-based and *will* have false positives, and its own docs
recommend grouping results by response content length and manually
verifying one representative of each length group with curl rather than
trusting the status code alone. Do the same here — see Section 7, which
is now a required step after every `403_bypass` call, not an optional
afterthought:

1. Run `403_bypass` (mode `exploit` for a first pass).
2. If `candidates_2xx` is empty, the endpoint held against this battery — move to the smuggling/parser-discrepancy techniques in Section 5, or conclude it's solid.
3. If non-empty, **group candidates by `length`** — several payloads returning the exact same byte count are almost always the same underlying response (commonly a generic SPA shell or error page serving 200 for everything, not a real bypass). Pick one candidate per distinct length and manually curl it with `curl_repro`.
4. For each one you curl: read the actual response body. Is this the real protected content (matches what you'd expect an authorized admin/staff/internal page to contain), or a homepage, a login redirect, a generic app shell, or an empty/error page wearing a 200? Only the former is a real bypass — see Section 7 for the full discipline before calling `record_finding`.

If you're testing something the tool doesn't cover, or verifying a single
specific idea by hand, work through the techniques below in order —
cheapest and most common first — trying each SEPARATELY (change one thing
per request) so you know exactly which technique worked if one does;
bundling multiple changes into one request makes a finding unreproducible
and unreportable.

## 1. Beginner: Path Manipulation

Many 403s come from a reverse proxy (nginx/Apache) doing path-based access
control that doesn't perfectly match how the *backend* parses the same
path. Try variations of the exact same logical path:

- Trailing slash: `/admin` → `/admin/` (and reverse)
- Double slash: `/admin` → `//admin`, `/admin//`
- Path traversal that resolves back to itself: `/admin/..;/admin`,
  `/admin/./`, `/./admin`, `/%2e/admin`
- Semicolon delimiters, especially against Tomcat/Spring backends:
  `/admin;`, `/admin;/`, `/;/admin`
- Case variation: `/admin` → `/Admin`, `/ADMIN` (case-sensitive backends
  behind case-insensitive proxy rules, or vice versa)
- URL encoding of individual characters: `/admin` → `/%61dmin`,
  `/adm%69n` (encode one letter at a time — bulk-encoding the whole path
  is a much weaker test since it's more likely to just be normalized away
  identically). Fully-encoded variants are also worth one try:
  `/%61%64%6d%69%6e`
- Append a null-ish or parser-confusing suffix: `/admin.json`, `/admin%00`,
  `/admin#`, `/admin?`, `/admin.`, `/admin;.css` (extension confusion —
  some proxies only apply auth rules to routes without a file-extension-like
  suffix, while the backend router ignores it and serves the same handler)
- Try the path directly against the backend if you know or can guess its
  real internal port/host, bypassing the proxy's rule entirely (only if
  this doesn't cross out of your task's scope).

## 2. Beginner: HTTP Method Override

The proxy/WAF rule may only be written for one method:

- If `GET /admin` is 403, try `POST`, `HEAD`, `PUT`, `PATCH`, `OPTIONS`,
  `DELETE`, `TRACE`, and non-standard verbs (`TRACK`, `DEBUG`) — sometimes
  only the documented method is actually gated.
- Method-override headers that some frameworks honor even when the real
  method differs: `X-HTTP-Method-Override: GET`,
  `X-HTTP-Method: GET`, `X-Method-Override: GET` on a `POST` request (or
  vice versa) — test both directions.

## 3. Intermediate: Header-Based Trust Spoofing

Internal infrastructure often trusts specific headers to mean "this
request already passed through a gateway/proxy that authenticated it" or
"this request originates from inside the network." This is the single
most-reported real-world 403 bypass class — `X-Forwarded-For: 127.0.0.1`
alone accounts for multiple disclosed reports: it exposed Acronis's
`nginx_status/` endpoint (#1224089), Yelp's internal Business Owner App
backend API (#1011767), and — per public writeups — Apache
`/server-status` pages on other programs the same way. Try adding these
to an otherwise-normal request (again, one at a time):

- `X-Forwarded-For: 127.0.0.1`, `X-Forwarded-For: localhost`
- `X-Forward-For: 127.0.0.1` (note the missing "ed" — Yelp's own bypass used this exact malformed variant, which their code path apparently still parsed)
- `X-Forwarded-Host: <target-host>`, `X-Host: localhost`
- `X-Originating-IP: 127.0.0.1`
- `X-Remote-IP: 127.0.0.1`, `X-Remote-Addr: 127.0.0.1`
- `X-Client-IP: 127.0.0.1`
- `X-Real-IP: 127.0.0.1`
- `X-Custom-IP-Authorization: 127.0.0.1`
- `Forwarded: for=127.0.0.1` (the standardized RFC 7239 header — worth trying alongside the X- variants, some stacks only parse one or the other)
- `X-Forwarded-Scheme: https` / `X-Forwarded-Proto: https` (if the app
  gates a route on assuming it's only reachable via internal HTTP)
- **URL rewrite/override headers, sent against the ALLOWED root path, not
  the restricted one:** some reverse proxies enforce access control only
  on the literal requested path while a header tells the upstream
  framework to actually route somewhere else — request `/` (or another
  allowed page) while adding `X-Original-URL: /admin` or
  `X-Rewrite-URL: /admin`. This is a distinct technique from the path
  manipulation in Section 1 — there you're changing what you ask for
  directly; here you're asking for something allowed while telling the
  backend to serve something else. This exact pair of headers is a
  disclosed, paid finding: MacKeeper's `/admin` sat behind a front nginx
  that returned 403 for the path directly, but the *backend* honored
  `X-Rewrite-Url`/`X-Original-Url` while the front server ignored them
  entirely, so requesting `/` with either header routed straight through
  (HackerOne #737323). A related variant — manipulating
  `X-Original-Url`/`X-Auth-Request-Redirect` alongside a `../`-laced path
  — got a Kubernetes ingress's external auth service to return 204
  instead of 401/403 (#1357948): worth combining this technique with
  Section 1's path tricks if the header alone doesn't work.
- Internal-service-style headers that a specific stack might trust:
  `X-Internal-Request: true`, `X-Gateway-Authenticated: true` — these are
  worth a shot generically but are far more likely to work if you've
  already fingerprinted the stack (e.g. a specific API gateway or service
  mesh product) and can check its actual trusted-header convention rather
  than guessing blind.

## 4. Intermediate: Referer / Origin Trust

Some access checks are (incorrectly) based on where the request claims to
have come from, not on actual authorization:

- `Referer: https://<target-host>/admin` or `Referer: https://<target-host>/`
- `Origin: https://<target-host>`
- If there's a known internal hostname or a `.internal`/`.local` pattern
  discovered elsewhere in recon, try that as the `Host` header while still
  connecting to the real IP (`curl -H "Host: internal-name" https://ip/path`).

## 5. Advanced: Request Smuggling / Parser Discrepancy

If the target sits behind a reverse proxy or CDN, the proxy and the
backend may parse an ambiguous request differently — this is a genuinely
higher-effort, higher-signal technique, not a first thing to try:

- Conflicting `Content-Length` and `Transfer-Encoding` headers (classic
  HTTP request smuggling setup) — only pursue this if you have a specific
  reason to suspect a proxy/backend mismatch (different server headers
  reported at different times, inconsistent behavior across retries), and
  be aware this can affect OTHER users' requests on a shared connection —
  treat it as a higher-risk technique to run carefully and sparingly, not
  something to hammer repeatedly.
- Duplicate headers with conflicting values (`Host` sent twice with
  different values, e.g.) — different components may read the first vs.
  last occurrence.

## 6. Advanced: Case-Sensitive / Encoding-Aware WAF Rule Gaps

If a WAF/reverse-proxy rule is written as a literal string match rather
than a normalized-path match:

- Unicode/overlong UTF-8 encoding of path characters
- Mixed encoding within one path segment
- Whitespace/tab injection in unexpected spots (`%09`, `%20` mid-path)

These are lower-probability, worth trying only after the cheaper
techniques above are exhausted, since they usually only work against
specific, older WAF implementations.

## 7. False-Positive Discipline (MANDATORY after every 403_bypass run — read before claiming ANY of the above worked)

A 403-bypass "win" is one of the easiest access-control findings to
accidentally fake yourself out on — and the `403_bypass` tool makes this
*easier* to fake yourself out on, not harder, because it fires dozens of
payloads unattended and hands back a bare list of status codes. A brute
force battery like this is explicitly known to produce false positives
(the public `forbidden` tool this pattern is modeled on ships the same
warning) — a target that just serves 200 for everything (an SPA shell, a
catch-all route) will show up as "bypassed" by every single payload in
the battery, which is meaningless. Every `candidates_2xx` entry is a lead,
not a finding, until it passes ALL of the following:

- **Confirm the response is actually the protected content, not a
  different 200.** A custom error page, a redirect-then-200 to a login
  page, or a generic app shell that happens to return 200 for any path
  (common in SPAs) are NOT a bypass. `curl_repro` from the tool gives you
  the exact request — run it yourself and read the actual response body —
  does it contain the real content/data the protected page should have,
  or generic/empty/error content wearing a 200 status?
- **Dedupe by response length first.** If several `candidates_2xx`
  entries share the same (or near-identical) `length`, they're almost
  certainly the same underlying response — verify one representative per
  distinct length, not every single payload individually.
- **Reproduce it as a clean, single request.** If you stacked five header
  tricks together and got through, remove them one at a time and re-test
  to find out which single change actually mattered — a report with an
  unnecessarily complex, unreproduced request chain reads as unreliable
  and may not even be the real cause.
- **Try it twice, freshly.** Confirm the bypass isn't just a cached
  response, a race-condition fluke, or a session that happened to still be
  valid from earlier in your testing.
- **Compare against a known-bad control.** Send the exact same bypass
  attempt against a path that definitely should NOT exist/be accessible —
  if that also returns 200, your "bypass" is actually the app's normal
  behavior (e.g. an SPA serving its shell for every path), not a real
  access-control flaw.

Only a candidate that survives every check above gets called a bypass —
everything else from a `403_bypass` run gets silently discarded, not
reported as a "possible" or "likely" finding.

## 8. Reporting

Once genuinely confirmed against the checks in Section 7, call
`record_finding` with the exact single technique that worked (e.g. "403
bypass via X-Forwarded-For: 127.0.0.1 spoofing" — not a vague "found a way
in"), the specific endpoint, and note in the finding what protected data
or functionality the bypass actually exposed — a bypass with no real
impact behind it is a much weaker finding than one that reaches real data.