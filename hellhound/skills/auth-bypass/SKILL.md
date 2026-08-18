---
name: auth-bypass
description: Universal methodology for authentication bypass and password reset flaws — discover endpoints dynamically via spidering, extract user/staff identities from raw data routes, check response-body token disclosure first, test host header injection, and escalate privileges post-authentication.
---

# AUTHENTICATION BYPASS METHODOLOGY

When testing authentication, password reset, or account recovery mechanisms on a web target, execute the following dynamic methodology.

## 1. Tool Selection & Execution Strategy
**CRITICAL RULE:** For a directed web application or authentication bypass task, **DO NOT waste time on network/infrastructure recon.**
- **DO NOT USE:** `subfinder`, `dnsx`, `naabu`, `nmap`, or DNS brute-forcing tools. These are irrelevant to web application logic testing.
- **DO USE:** 
  - `spider` to crawl the application, identify all exposed routes, extract forms, and map API endpoints.
  - `curl` with proper HTTP methods, headers (`Content-Type: application/json`), and structured payloads (`json`/`data`) to inspect raw responses.

## 2. Dynamic Surface Discovery & Flow Mapping
Do not assume or guess endpoint names. Always extract the real application structure from spidering results:
1. **Discover Routes & Endpoints:** Identify from the crawl:
   - Discovered API endpoints and data feeds (e.g., content feeds, article routes, user directories, configuration endpoints).
   - Authentication routes: Login forms, password recovery/forgot endpoints, and password reset endpoints.
2. **Inspect Discovered Data Routes First:**
   - Modern single-page and web applications fetch backend data via API routes.
   - For **every** data/content API endpoint discovered during crawling (e.g., posts, news, staff, users), issue a `GET` request via `curl` to examine the full raw JSON output BEFORE attempting any authentication or recovery requests.
   - Harvest valid target identities (e.g., staff emails, usernames, roles, admin designations) from response objects.
   - **CRITICAL:** Do NOT guess or invent fake placeholder emails (like `test@example.com` or `admin@local`). Real backend recovery and reset logic only activates for existing, registered identities harvested from the application.

## 3. Response Body Token Disclosure (Direct Flaw Check)
Before testing out-of-band vectors or complex chains, check if the application leaks the password recovery token directly back to the client:

1. **Submit Recovery Request:**
   Send a `POST` request to the application's discovered recovery/forgot endpoint using a harvested, valid identity:
   ```json
   {
     "tool": "curl",
     "args": {
       "url": "<discovered_recovery_endpoint>",
       "method": "POST",
       "headers": {"Content-Type": "application/json"},
       "json": {"<identity_field>": "<harvested_identity_email>"}
     }
   }
   ```
2. **Inspect the Full Response Body:**
   - Read the entire JSON response. Look for any disclosure of tokens, reset URLs, confirmation codes, or preview objects (e.g., `token`, `reset_url`, `preview`, `code`, or unique session identifiers).
   - *Note on Enumeration Safeguards:* If the endpoint returns a generic success message when tested with non-existent or placeholder emails, this does not confirm the endpoint is secure. Re-test using confirmed, harvested user accounts before ruling out leakage.

3. **Complete the Authentication Chain:**
   - If a reset token/code is leaked in the response, submit it to the application's discovered reset endpoint:
     ```json
     {
       "tool": "curl",
       "args": {
         "url": "<discovered_reset_endpoint>",
         "method": "POST",
         "headers": {"Content-Type": "application/json"},
         "json": {
           "<token_field>": "<leaked_token>",
           "<password_field>": "NewSecurePassword123!"
         }
       }
     }
     ```
   - Log in via the discovered login endpoint using the updated credentials:
     ```json
     {
       "tool": "curl",
       "args": {
         "url": "<discovered_login_endpoint>",
         "method": "POST",
         "headers": {"Content-Type": "application/json"},
         "json": {
           "<identity_field>": "<harvested_identity_email>",
           "<password_field>": "NewSecurePassword123!"
         }
       }
     }
     ```
   - Verify access to privileged or authenticated areas (e.g., user profiles, admin consoles, internal records) using the resulting session.
   - **MANDATORY VISUAL PROOF (gowitness):** Immediately capture visual Proof of Concept using `gowitness` on the authenticated web UI (e.g. `/pulse/portal`, `/pulse/dashboard`, `/pulse/admin`, `/pulse/profile`) using the acquired session cookie:
     ```json
     {
       "tool": "gowitness",
       "args": {
         "url": "<discovered_authenticated_portal_url>",
         "headers": {"Cookie": "<session_cookie_e.g._p_sid=...>"}
       }
     }
     ```
   - **Record Verified Finding:** Log the confirmed vulnerability in structured memory via `record_finding`:
     ```json
     {
       "tool": "record_finding",
       "args": {
         "title": "Account Takeover via Password Reset Token Leakage",
         "kind": "auth_bypass",
         "severity": "critical",
         "request_ref": "<discovered_recovery_endpoint>",
         "note": "Password reset token disclosed directly in HTTP response body; allowed full account takeover of staff/admin account."
       }
     }
     ```

## 4. Host Header Injection (Password Reset Poisoning)
If the response body does not directly leak the token:
- Test if the backend dynamically constructs the reset URL using the client-supplied `Host` header:
  - Submit the password recovery request with a modified `Host` or `X-Forwarded-Host` header pointing to an external domain or controlled listener.
  - If the server accepts the header and issues a reset email containing the poisoned host, the reset token will be delivered to the attacker-controlled server upon user click.

## 5. Post-Authentication Privilege Assessment
Once authenticated into any account:
- Inspect session tokens, user profile endpoints, and role attributes.
- If access is restricted or non-privileged, identify high-privilege accounts (administrators, managers, owners) from initial discovery data and re-apply the recovery flow against the elevated account.
- Probe for access to administrative panels, sensitive endpoints, or internal data APIs to evaluate total business impact.

## 6. Proof of Concept & Bounty Escalation Documentation
When reporting an authentication bypass or account takeover:
1. **Concrete Evidence / PoC:**
   - Document the full reproduction chain with exact requests, response snippets, leaked tokens, and resulting authenticated session cookies.
   - Highlight any exposed high-value assets (e.g., admin controls, EHR/PHI records, internal API keys, database connection strings, S3/storage bucket links).
   - Reference the visual PoC screenshot captured via `gowitness` demonstrating authenticated access to the confidential member/admin portal.
2. **Impact Escalation for Maximum Bounty:**
   - **Severity Rating:** Classify under VRT/CVSS (typically **Critical / High** for ATO).
   - **Business Impact:** Clearly explain how taking over a privileged identity allows unauthorized data exfiltration, compliance violations (e.g., HIPAA/GDPR), and complete administrative compromise.
   - **Remediation Steps:** Advise on generating cryptographically secure, out-of-band delivery of reset tokens, removing debug previews in production, and implementing rate limiting.

