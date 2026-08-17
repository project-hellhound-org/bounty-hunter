---
name: auth-bypass
description: Targeted methodology for authentication bypass and password reset flaws — check response-body token disclosure FIRST (most common, no header tricks needed), then host header injection, email leak via API/HTML scraping, and REST token manipulation. Always follow through to privilege escalation once a session is obtained.
---

# AUTHENTICATION BYPASS METHODOLOGY

When dealing with a password reset or "forgot password" auth flow, follow these exact steps to uncover logic flaws.

## 1. Tool Selection & Execution Strategy
**CRITICAL RULE:** For a directed authentication bypass or specific web endpoint task, **DO NOT waste time on infrastructure recon.**
- **DO NOT USE:** `subfinder`, `dnsx`, `naabu`, `nmap`, or any port scanning / DNS brute-forcing tools. These are completely irrelevant to a single-endpoint web application task and waste time.
- **DO USE:** 
  - `curl` for manual HTTP requests and checking headers/bodies.
  - `spider` or `katana` for discovering endpoints, content discovery, and finding leaked information (like emails in HTML).
  - Web interaction tools to scrape HTML, extract sensitive data, and send `POST` requests to authentication endpoints.
  
Keep it straightforward: Do the directed task using only the necessary web-layer tools.

## 2. Map the Complete Flow
- Identify the exact API endpoints used for the authentication flow, such as:
  - `/api/auth/forgot` or similar (POST)
  - `/api/auth/login` (POST)
  - `/api/auth/reset` or similar (POST/GET)
- Enumerate valid users. If the app returns a generic success message on forgot password but you don't know the target email, you MUST find the email.

## 3. Deep Content Scraping & API Inspection for Leaks
- Do not just rely on HTML responses or frontend scraping. Modern SPAs load their data from backend APIs.
- **CRITICAL:** If the spider discovers ANY raw data API endpoints (e.g., endpoints returning JSON, content feeds, user lists, or configuration), you MUST fetch those exact endpoints using `curl`. Do not assume the endpoint names; inspect the spider's output for anything that looks like an API route.
- JSON responses from REST APIs often contain unfiltered backend data, including author emails, IDs, and hidden fields that are completely invisible in the frontend HTML.
- Always extract all email addresses from BOTH the HTML source and the raw JSON API responses. Authors or staff often leak their corporate email in the author bio or metadata.

## 4. Response Body Token Disclosure (check this FIRST — simplest, most common)
Before trying anything clever (host header injection, log scraping), just look at what the
`forgot`/`reset-request` endpoint's own HTTP response actually contains.

- `POST /api/auth/forgot {"email": "<harvested-email>"}` and read the **full, untruncated**
  response body — not a summary, the actual JSON.
- If the response includes ANY field that looks like a reset token, code, or link
  (`token`, `reset_token`, `prt_...`, a `resetUrl` containing a query param, etc.) directly in
  the JSON, the app is leaking it straight back to the caller. No email access, no header
  tricks, no log scraping needed — you already have it.
- Immediately use that token: `POST /api/auth/reset {"token": "<leaked>", "password": "<new>"}`,
  then `POST /api/auth/login` with the new password to get an authenticated session.
- **A generic, enumeration-safe message on the FIRST attempt (e.g. `{"ok":true,"message":"If
  an account exists..."}`) does not rule this out.** That response is often only safe for
  *unknown* emails — the token may still appear in the body when the email you send is a real,
  valid account. If your first test used a guessed or incomplete email and got the generic
  message, that is not a dead end: go back, get the COMPLETE harvested email (see the note
  below on truncation), and retry `forgot` with the exact, full, correct address before
  concluding the endpoint is safe.
- **Never accept a truncated identifier.** If an email, token, or ID you harvested from an
  API response looks cut off (ends mid-word, ends without a TLD, ends with "..."), that is a
  display/preview artifact, not the real data — fetch the full raw response for that specific
  field before using it. Testing a truncated email will fail even when the real one works,
  and reads to a human reviewer as "gave up," not "confirmed safe."

## 5. Once You Have a Session: Always Check for Escalation
Getting into ANY account via the flaws above is not the end of the task if the target says
"reach the admin console" / "take over an employee account" — it means you're not done yet.
- Check the authenticated user's own role/permissions (`/api/user/me` or similar) immediately
  after login.
- If the account you took over isn't privileged, look at what else the harvested identity data
  suggested (job titles, roles, or bio text implying elevated privilege, e.g. "Owner,"
  "Admin," "Manager," any C-level/leadership title) — that's a signal to specifically target
  THAT person's account with the forgot/reset chain above, not a random or first-found account.
  Never assume a specific name or title in advance — read it from what the target's own pages
  actually return.
- Once authenticated as a privileged user, check for further exposed secrets (API keys,
  internal config, storage bucket names/URLs) that a real business-impact report would need —
  these often appear directly in an admin-only API response once you're actually logged in.

## 6. Host Header Injection (if response-body disclosure isn't present)
If the application uses a REST API to send a password reset link to the user:
- How does the server know what domain to put in the reset link? It often uses the `Host` header from your HTTP request.
- **The Attack:** Intercept the forgot password request. Change the `Host` header to your own controlled server (e.g., `Host: attacker.com` or a webhook).
- When the server generates the email to the target, the reset link will point to `http://attacker.com/reset?token=XYZ`. 
- You receive the token on your server and can then use it on the real application to change the target's password.

## 7. The Direct-to-Server Reset Link Attack
Sometimes the backend is misconfigured to send the reset link *to the server's own logs* or to *the client response*, or the application blindly trusts the reset link generation.
- Initiating the forgot password flow for the leaked email might generate a backend reset link that is accessible or logged.
- **VULNERABILITY CHECK:** If the reset link is sent to the web server's own endpoint instead of an external email, you might be able to capture it if there's a misconfigured logging endpoint, or if you can manipulate the host header to point back to an endpoint you control or can view.
