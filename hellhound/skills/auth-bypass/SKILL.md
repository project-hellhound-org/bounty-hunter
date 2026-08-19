---
name: auth-bypass
description: Universal methodology for authentication bypass, JWT manipulation (alg:none confusion, RSA public key misuse), password reset flaws, response-body token disclosure, host header injection, and post-authentication privilege escalation.
---

# AUTHENTICATION BYPASS METHODOLOGY

When testing authentication, session management, JWT tokens, password reset, or account recovery mechanisms on a web target, execute the following dynamic methodology.

## 1. Tool Selection & Execution Strategy
**CRITICAL RULE:** For a directed web application or authentication bypass task, **DO NOT waste time on network/infrastructure recon or heavy crawling up front.**
- **DO NOT USE:** `subfinder`, `dnsx`, `naabu`, `nmap`, or DNS brute-forcing tools.
- **DO NOT LAUNCH IMMEDIATE SPIDERS:** Running an automated multi-depth spider immediately creates massive traffic and log noise on production environments.
- **SURGICAL RECON VIA `CURL` FIRST:** 
  - Use `curl` to fetch the landing page HTML, `/login`, embedded script files (`.js`), forms, and HTTP headers.
  - Parse JavaScript bundle files with `curl` to identify API route tables, authentication handlers, and state variables without making hundreds of crawler requests.
  - Only use `spider` as a fallback if surgical inspection yields no routes.

## 2. Dynamic Surface Discovery & Flow Mapping
Do not assume or guess endpoint names. Extract the real application structure from surgical responses:
1. **Discover Routes & Endpoints:** Identify from HTML/JS:
   - Discovered API endpoints and data feeds (e.g., content feeds, article routes, user directories, configuration endpoints, JWKS routes).
   - Authentication routes: Login forms, session endpoints, password recovery/forgot endpoints, and password reset endpoints.
2. **Inspect Discovered Data Routes First:**
   - Modern single-page and web applications fetch backend data via API routes.
   - For **every** data/content API endpoint discovered, issue a `GET` request via `curl` to examine the full raw JSON output BEFORE attempting any authentication or recovery requests.
   - Harvest valid target identities (e.g., staff emails, usernames, roles, admin designations) from response objects.
   - **CRITICAL:** Do NOT guess or invent fake placeholder emails (like `test@example.com` or `admin@local`). Real backend recovery, reset, and authentication logic only activates for existing, registered identities harvested from the application.

## 2.1 Authenticated Post-Login Reconnaissance & Intel Mining
When you achieve an initial foothold or low-privilege login (e.g. via self-registration, default credentials, or session cookie):
1. **Low-Noise Route Probing**: Use `curl` to visit internal application pages (directories, member lists, profile views, account settings, about pages) with the session cookie.
2. **Deep Content Mining Across Application Views**:
   - Read the HTML and embedded script responses carefully to harvest:
     - Target user profiles, account identifiers, and role designations.
     - Personal information (biography, identifiers, security question indicators like education, family details, dates).
     - Account recovery, password reset, or security challenge endpoints.
     - Client-side application state (e.g. `window.__INITIAL_STATE__`, `window.__CONFIG__`, or embedded JSON objects in `<script>` tags) containing tokens, API keys, or role definitions.
3. **OBJECTIVE FIDELITY & STEPPING STONES**:
   - Distinguish between stepping-stone accounts (e.g. normal user / staff / intermediate account) and the PRIMARY target account requested by the user (e.g. Administrator / designated high-privilege account / Owner).
   - **Directory Listing is NOT Account Takeover**: Viewing a list table at `/users`, `/staff`, or `/directory` lists users. Seeing the target user in a list table does not mean you have taken over their account. To verify your active identity, check `/profile`, `/me`, or the active session token.
   - Gaining access to a stepping stone or discovering an impersonation token for a normal user is an intermediate foothold for mechanism learning—it is NOT the completion of the objective.
   - **DO NOT** take completion screenshots or claim full account takeover when only a stepping-stone account is accessed. Continue the chain against the PRIMARY target!

## 2.2 Differential Probing & Mechanism Reverse Engineering (Session Delegation & Token Swapping)
When an action or mutation targeting a high-privilege victim (e.g., `<endpoint>/<victim_id>/impersonate` or `<endpoint>/<victim_id>/switch`) returns `403 Forbidden` ("Cannot impersonate admin / unauthorized") or `404 Not Found`:
1. **Differential Probing on Accessible/Allowed Accounts**:
   - Test the exact same endpoint against lower-privilege, normal, or self accounts (e.g. `<endpoint>/<allowed_user_id>/...` or your current account ID) using `GET` and `POST`.
   - Observe how the backend processes valid operations:
     - Does the successful response return a one-time token, delegation key, or hint URL (e.g. `{"auth_token": "...", "hint": "<auth_handler>?token=..."}`)?
     - Does it issue an HTTP 302 redirect with a query parameter (e.g. `Location: <auth_handler>?token=<token>`)?
2. **Artifact Inventory Cross-Check (Mechanical Field-Name Matching)**:
   - **CRITICAL RULE**: Before searching for a new token or firing new recon, check whether a matching token was already harvested earlier in this session from any staff/user/profile endpoint in the **Harvested Artifact Inventory**.
   - Before constructing a request to any endpoint accepting a parameter matching `token|key|secret|auth|session|sid|delegation`, cross-check every entry in the Harvested Artifact Inventory for a plausible match, regardless of exact field-name spelling. A field named `auth_token`, `access_token`, `delegation_key`, or `cmo_secret` are all candidates for a parameter named `token`. Do not conclude a new token must be found until the existing inventory has been checked.
3. **Artifact Chaining (Token Parameter Injection)**:
   - Identify the victim's authentication token, profile secret, or identifier previously harvested from client-side JavaScript state objects, profile endpoints, or API responses.
   - Supply the victim's token directly to the discovered delegation or authentication handler:
     ```json
     {
       "tool": "curl",
       "args": {
         "url": "https://<target>/<auth_handler>?token=<victim_harvested_token>",
         "method": "GET"
       }
     }
     ```
   - Check if the response establishes a session for the victim (`Set-Cookie: session=<victim_id>` or returns a privileged JWT).
   - Use the newly elevated session to access protected endpoints and retrieve confidential proof.

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
   - **MANDATORY VISUAL PROOF (gowitness):** Immediately capture visual Proof of Concept using `gowitness` on the authenticated web UI (e.g. the discovered user dashboard, settings, or administrative console) using the acquired session cookie/token:
     ```json
     {
       "tool": "gowitness",
       "args": {
         "url": "<discovered_authenticated_portal_url>",
         "headers": {"Cookie": "<session_cookie_e.g._session=...>"}
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

When the application uses JSON Web Tokens (JWT) for authentication (stored in session cookies or passed in the `Authorization: Bearer <jwt>` header):

> [!IMPORTANT]
> **Token Type Distinction:** Always verify the token structure before applying JWT attacks.
> - A valid JWT always starts with `eyJ` and consists of 3 dot-separated base64url segments (`<header>.<payload>.<signature>`).
> - If the token/cookie is an opaque session ID (`sess_...`, `connect.sid`, `PHPSESSID`, or a hex string without dots), the application uses server-side session management. **DO NOT attempt JWT attacks or run `jwt_forge` on opaque cookies.** Instead, pivot to the `access-control` skill to test Mass Assignment, client JS analysis, and nested property injection (e.g. `{"metadata": {"entitlements": {"admin": true}}}`).

### A. Decode and Analyze Existing Tokens
1. Split the token into Header, Payload, and Signature (`<header>.<payload>.<signature>`).
2. Base64url-decode both Header and Payload to inspect:
   - Header: `alg` (e.g. `HS256`, `RS256`, `none`), `typ`, `kid`, `jwk`, `jku`.
   - Payload: Subject (`sub`), email, username, role flags (`role`, `roles`, `isAdmin`, `is_admin`, `group`, `user_type`), permissions, and expiration (`exp`).

### B. Attack Vector 1: Algorithm Confusion (`alg: "none"`)
Many insecure JWT verification implementations accept tokens signed with the `none` algorithm or fail to enforce cryptographic signature verification when `alg` is set to `none` (case-insensitive variants).

1. **Construct Unsigned Token Header:**
   - Standard: `{"alg": "none", "typ": "JWT"}`
   - Filter-bypass variants: `{"alg": "None"}`, `{"alg": "NONE"}`, `{"alg": "nOnE"}`
2. **Forge Privileged Payload:**
   - Set identity to harvested staff/administrator identity or elevate role parameters (e.g. `{"sub": "<harvested_admin_username>", "email": "<harvested_admin_email>", "role": "admin", "admin": true, "isAdmin": true, "exp": 9999999999}`).
3. **Assemble Unsigned JWT:**
   - Base64url-encode Header and Payload (replacing `+` with `-`, `/` with `_`, and stripping all `=` padding).
   - Concatenate Header and Payload with a trailing dot and **NO** signature:
     ```
     <base64url_header>.<base64url_payload>.
     ```
4. **Submit and Verify:**
   - Send `curl` request to discovered protected/administrative endpoints (e.g. discovered dashboard, profile, or management routes) with the forged token in the `Cookie` or `Authorization` header.
   - If accepted (200 OK / privileged data returned), proceed to visual capture and finding recording.

### C. Attack Vector 2: RSA Public Key Misuse (RS256 → HS256 Algorithm Confusion)
When an application uses RS256 (asymmetric signing where the server signs with a private key and verifies with a public key), vulnerable JWT libraries allow switching the algorithm to HS256 (symmetric HMAC). If the server passes its RSA public key to the generic verification function, the HMAC algorithm uses the **public key as the HMAC secret**:

1. **Obtain the Server's RSA Public Key:**
   - Check standard public key endpoints: `/.well-known/jwks.json`, `/api/auth/jwks`, `/public.pem`, `/cert.pem`, TLS certificates, or frontend bundles.
   - Convert JWK format to PEM string if necessary (`-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----`).
2. **Forge Header with Symmetric Algorithm:**
   - `{"alg": "HS256", "typ": "JWT"}`
3. **Sign Payload with Public Key as Secret:**
   - Sign the Base64url `<header>.<payload>` using HMAC-SHA256 with the server's public key text (or raw public key bytes) as the HMAC key.
4. **Submit and Test:**
   - Send the forged token to discovered authenticated API routes or web dashboards.

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

## 8. Multi-Vector Attack Progression & Artifact Correlation Checklist
When tasked with account takeover or high-bounty hunting, execute the full attack progression across all orthogonal vectors:

```
[Target Identity Harvested (<victim_user_id> / <target_username> / <target_role>)]
  │
  ├── Vector 1: Direct Client Data & Credential Leaks
  │     └─ Mine embedded script objects, comments, and profile/account responses
  │        -> Found credentials/secrets? Authenticate directly via login endpoints
  │
  ├── Vector 2: Differential Mechanism Learning & Parameter Injection
  │     └─ If <endpoint>/<victim_id>/action returns 403 / Forbidden:
  │        1. Probe allowed object (<endpoint>/<allowed_id>/action) to learn mechanism
  │        2. Discover underlying handler: <handler>?param=<token>
  │        3. Swap victim's harvested token -> <handler>?param=<victim_token>
  │
  ├── Vector 3: Password Reset & Security Question Intelligence
  │     └─ Mine directories and profile views for personal context (education, history, dates)
  │        -> Submit to recovery or challenge verification flows
  │        -> Inspect response bodies for leaked tokens or test Host Header injection
  │
  ├── Vector 4: Access Control & Mass Assignment
  │     └─ Test account update routes with discovered nested roles and attributes
  │
  └── Vector 5: Session Architecture & JWT Manipulation
        └─ If JWT: alg:none, RS256->HS256 public key confusion, claim tampering
```

**Rule of Exhaustion:** Never conclude that an account cannot be compromised or that no bug exists until all viable vectors above have been tested and verified against the live target.

