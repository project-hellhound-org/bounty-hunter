---
name: server-side-parameter-pollution
description: Comprehensive real-world methodology for discovering and exploiting Server-Side Parameter Pollution (SSPP) and internal query/path/JSON injection across backend microservices, internal APIs, and upstream integrations. Covers client-side JS mining for dynamic API schemas, delimiter (%26) and truncation (%23) bisection error oracles, parameter override, token harvesting, dynamic form payload reconstruction, and full privilege escalation / account takeover verification.
---

# SERVER-SIDE PARAMETER POLLUTION (SSPP) METHODOLOGY

Server-Side Parameter Pollution (SSPP) occurs when a front-facing application takes user input and concatenates it — unencoded or unsanitized — directly into an HTTP request, URL path, query string, or structured payload dispatched to an internal microservice, back-end API, or third-party service.

Because this internal request is executed entirely server-side, it is invisible to client-side network inspectors. The vulnerability is discovered and exploited by turning the back-end's validation logic and error messages into a deterministic bisection oracle, and by mining client-side JavaScript assets to uncover the internal API's schema.

---

## 1. Attack Surface Mapping & Candidate Flow Discovery

SSPP commonly occurs in workflows where user input is forwarded to an internal backend service or microservice:

1. **Authentication, Recovery & Password Reset Flows** (High Impact):
   - Endpoints handling account lookup, password reset requests, magic link generation, or MFA verification.
   - The front-end accepts a user identifier (`username`, `email`, `account_id`), and the back-end constructs an internal query to fetch the user's recovery method or dispatch a token.
2. **User Search, Directory & Autocomplete Features**:
   - Search filters forwarded to internal directory, catalog, or tenant lookups.
3. **Profile, Settings & Resource Updates**:
   - Multi-field update endpoints where profile fields are assembled into internal service requests.
4. **Proxied Third-Party & Microservice Integrations**:
   - Webhooks, payment gateway callbacks, notification dispatchers, and report generators.

---

## 2. Dynamic Asset Recon & Internal Schema Discovery

When a candidate input point is discovered, **never guess parameter or field names blindly**. Front-end applications routinely bundle API schemas, field names, and route formats needed to communicate with internal endpoints.

### Dynamic Client-Side Recon Workflow:
1. **Extract Script References**:
   - Inspect the target HTML response for all `<script src="...">` tags, Webpack/Vite chunk manifests, and linked bundles (e.g. `/static/js/...`, `/dist/...`, `/assets/...`, `app.js`, `main.js`, `auth.chunk.js`, `runtime.js`).
2. **Fetch and Analyze Script Content**:
   - Fetch each discovered script using `curl` and mine for:
     - **Internal Parameter & Property Names**: Look for property names, object keys, query parameters, or string constants such as:
       - `field`, `reset_token`, `resetToken`, `token`, `temp_token`, `temp-token`, `code`, `recovery_code`
       - `email`, `role`, `status`, `secret`, `api_key`, `verification_key`, `account_id`
     - **API Routes & Handler Formats**: Look for path definitions and query string templates (e.g. endpoints accepting token query parameters or POST bodies).
     - **Client-Side State Handlers & Form Submission Logic**: Determine how the frontend expects parameters to be submitted to complete authentication, reset, or update actions.

---

## 3. Core Detection Technique: Bisection Probing & Error Oracles

> [!IMPORTANT]
> **CRITICAL SSPP ERROR ORACLE RULES — HTTP 400 IS CONFIRMATION, NOT FAILURE:**
> In Server-Side Parameter Pollution, HTTP 400 / 422 error messages (e.g. `"Parameter is not supported"`, `"Field not specified"`, `"Invalid field"`, `"Missing parameter"`) are **POSITIVE CONFIRMATION** of internal query concatenation and parameter leakage, NOT a rejection or failed exploit!
> - **Error: `"Parameter is not supported"` / `"Unknown parameter"`**: Confirms your injected `%26<key>=<val>` reached the backend query parser!
> - **Error: `"Field not specified"` / `"Missing parameter <name>"`**: Confirms truncation (`%23`) successfully stripped the server's default parameter, AND the error message reveals the exact name of the backend parameter (e.g., `field`)!
> - **Error: `"Invalid field"`**: Confirms the backend parameter (`field`) exists in the backend API, but the value you provided is not in its allowed enum/database column list!
> - **NEVER ABORT OR DECLARE FAILURE** when seeing these 400 responses! Treat them as active bisection clues and immediately proceed to override the discovered parameter.

```mermaid
flowchart TD
    A["Baseline Request (Valid & Invalid)"] --> B["Delimiter Injection (%26 / &)"]
    B --> C{"Error Changed?"}
    C -- "Yes ('Unknown parameter / Parameter not supported')" --> D["SSPP Confirmed: Query Concatenation"]
    C -- "No / Identical" --> E["Test Path (%2f) or JSON (\") Injection"]
    D --> F["Truncation Injection (%23 / #)"]
    F --> G["Leak Backend Parameter Name ('Field not specified')"]
    G --> H["Parameter Override (%26<param>=<target_field>%23)"]
    H --> I["Exfiltrate Token / Secret / State"]
```

### Exact Step-by-Step Payload Construction:

1. **Step 1: Baseline Characterization**
   - Send valid known entity (e.g. `<user_param>=<valid_user>`). Note baseline response code, message, and length.
   - Send invalid entity (e.g. `<user_param>=<non_existent_user>`). Note response difference.

2. **Step 2: Delimiter Injection Probe (`%26` / `&`)**
   - Append an URL-encoded ampersand (`%26`) and an arbitrary dummy key-value pair:
     ```http
     <user_param>=<valid_user>%26x=y
     ```
   - **Oracle Check**: If response is `"Parameter is not supported"`, `"Unknown parameter 'x'"`, or `"Invalid parameter"`, unencoded query concatenation is **CONFIRMED**.

3. **Step 3: Truncation Injection Probe (`%23` / `#`)**
   - Append an URL-encoded hash (`%23`) directly at the end of the user input with **nothing after it**:
     ```http
     <user_param>=<valid_user>%23
     ```
   - **Oracle Check**: If response shifts to `"Field not specified"`, `"Missing required parameter"`, or `"Parameter 'field' is required"`, truncation succeeded and stripped trailing server parameters (e.g. `&field=email`), **revealing the backend parameter name (`field`)**.

4. **Step 4: Parameter Override & Token Exfiltration (`%26<param>=<target_field>%23`)**
   - Construct the full override payload using:
     - `%26` to introduce the leaked backend parameter.
     - `<discovered_param>=<candidate_field>` using fields harvested from JavaScript analysis (e.g. `reset_token`, `resetToken`, `token`, `temp_token`, `secret`, `recovery_code`).
     - `%23` at the very end to truncate original trailing backend parameters.
     ```http
     <user_param>=<target_user>%26<discovered_param>=<candidate_field>%23
     ```
     *(Example: `username=<target_user>%26field=reset_token%23`)*
   - **Iterate Candidate Fields**: If the backend returns `"Invalid field"`, test the next candidate property mined from client JavaScript or standard schemas until HTTP 200 / token reflection is achieved.
   - **Extract Leaked Token**: The backend returns the target user's actual password reset token, sensitive attribute, or secret in the response body.

---

## 4. End-to-End Autonomous Exploitation & Dynamic Token Consumption

Never stop or output summaries after leaking a reset token, credential, or secret. Dynamically determine how the application consumes the artifact and chain it through to full verification:

1. **Trace Token Consumption Logic from Client Code & Schemas**:
   - As soon as a token, key, or secret is exfiltrated, inspect the client-side JavaScript assets and application forms to identify how and where the application consumes it:
     - **URL Query / Route Parameter**: Check client scripts for `URLSearchParams`, `window.location.search`, route parameters (e.g. `:token`, `{code}`), or query parameter keys used during verification or redirection.
     - **Form Input Fields**: Check HTML forms for hidden or visible input elements (`<input name="...">`) designed for verification keys, tokens, or codes.
     - **JSON API Payloads**: Check client scripts for `fetch()` / `axios` calls that dispatch verification tokens in JSON bodies.
     - **Authentication Headers**: Check if the token serves as a bearer token or custom header (`Authorization: Bearer <token>`, `X-Auth-Token: <token>`).
2. **Invoke Consumption Handler & Extract Form/API Schema**:
   - Request the discovered handler endpoint using the exact parameter structure identified in the client-side code.
   - If an HTML form is returned, parse all required `<input name="...">` attributes, CSRF tokens, and password fields directly from the response.
   - If an API endpoint is targeted, construct the JSON payload matching the expected schema.
3. **Submit State-Changing Request (Password Reset / Account Claim)**:
   - Submit the POST/PUT request containing all discovered parameters (CSRF token, target identity, exfiltrated token/secret, new password, confirmation fields):
     ```http
     POST <discovered_action_endpoint>
     Content-Type: <application/x-www-form-urlencoded OR application/json>

     <discovered_payload>
     ```
   - Confirm successful state change (e.g. HTTP 302 redirect or JSON confirmation status). If a validation error indicates a missing parameter, dynamically add the requested field and retry.
4. **Authenticate as Target & Verify Elevated Access**:
   - Authenticate with the newly set credentials or acquired token via the application's login handler.
   - Confirm authentication success and store the resulting session cookie or bearer token.
   - Navigate to the privileged portal or administrative dashboard using `curl`.
5. **Execute Mission Objectives & Human Approval Handling**:
   - Carry out the required verification or bounty objective (e.g. reading privileged data, accessing administrative consoles, testing account deletion).
   - *Note*: Destructive actions (e.g. DELETE, purge, wipe) are safeguarded by Hellhound's interactive approval gate in the CLI. When prompted, approve or review the action safely.
6. **Evidence Capture & Finding Registration**:
   - Capture visual proof using `gowitness` of the authenticated administrative console or privileged dashboard.
   - Record the verified vulnerability using `record_finding`.
   - Output "DONE".

---

## 5. Modern SSPP Variants & Architectures

### A. REST URL Path Parameter Pollution
When user input is placed into a URL path (e.g. `/api/v2/users/{input}/status`):
- Inject path traversal sequences (`..%2f` or `../`) to manipulate back-end routing:
  - `<param>=..%2f<target_user>%2f<discovered_field>%2f<target_property>`
  - Re-route from modern guarded endpoints (`/v2/`) to legacy unguarded endpoints (`/v1/`).

### B. Structured-Format Injection (JSON / XML)
When user input is concatenated unencoded into internal JSON/XML bodies:
- Inject sibling JSON keys or breakout structures:
  - Input: `user", "role": "admin", "is_verified": true, "dummy": "`
  - Resulting internal payload: `{"username": "user", "role": "admin", "is_verified": true, "dummy": "", "tier": "standard"}`
- Always close existing strings and balance JSON/XML syntax to prevent unparseable parser errors.

### C. Classic HTTP Parameter Pollution (HPP / WAF Evasion)
Sending multiple parameters with the same name to exploit discrepancies between reverse proxies, WAFs, and backend application servers:
- Test duplicate parameter behavior across the stack:
  - `?id=1&id=2`
  - Node/Express & PHP: Last parameter wins (`id=2`).
  - ASP.NET: Parameters concatenated with comma (`id=1,2`).
  - Java Servlet: First parameter wins (`id=1`).
- Split malicious payloads across duplicate parameters so each half bypasses WAF inspection while back-end concatenation reassembles the exploit.

---

## 6. Strict Verification Gate: Finding Validity Rules

Do not report SSPP based solely on differing error strings. A valid finding must satisfy at least one of these criteria:

- [x] **Unauthorized Data Disclosure**: Extraction of sensitive tokens, passwords, reset keys, or internal fields belonging to another user.
- [x] **State Manipulation & Account Takeover**: Successful alteration of account state, password reset, or authorization privilege escalation.
- [x] **Security Control Bypass**: Reaching restricted backend routes, bypassing API versioning guards, or executing WAF-evaded payloads.

---

## 7. Recording Verified Findings

Record findings using `record_finding`:
- `title`: "Server-Side Parameter Pollution Leading to Account Takeover / Internal Token Disclosure"
- `kind`: "server_side_parameter_pollution"
- `severity`: "CRITICAL" (when leading to account takeover or token leakage) / "HIGH"
- `request_ref`: Exact vulnerable endpoint, method, parameter, and payload
- `note`: Full bisection reconstruction narrative, harvested JavaScript evidence, exfiltrated token/data, and complete reproduction steps.
