---
name: access-control
description: Methodology for broken access control — horizontal/vertical privilege escalation, IDOR, deep mass assignment (nested property injection), client JavaScript reverse engineering, and role manipulation. Use when the objective involves reaching higher-privilege accounts, administrative consoles, another user's data, or bypassing server-side authorization from any authenticated or self-registered position.
---

# ACCESS CONTROL & PRIVILEGE ESCALATION METHODOLOGY

This applies whenever you have (or can get) ANY authenticated session — even a freshly self-registered, zero-privilege account — and the objective involves reaching something that account shouldn't be able to reach: another user's data, an owner console, billing secrets, staff tools, or elevated roles.

---

## 1. Pre-Auth: Foothold & Session Architecture Discovery

Before testing access control, establish your session foundation:

1. **Self-Registration as Foothold:**
   - If self-registration is open, register a standard account immediately. A freshly registered zero-privilege account is the ideal launchpad for privilege escalation and mass assignment audits.
2. **Session Architecture Identification (Opaque Cookie vs. JWT):**
   - **Opaque Session Cookie:** e.g., `m_sid=sess_df11d034...`, `connect.sid=...`, `PHPSESSID=...`, or 32-character hex/random strings. These are server-side session pointers. **NEVER attempt JWT forgery (`jwt_forge`, `alg: none`) on opaque session IDs.**
   - **JSON Web Token (JWT):** e.g., `eyJhbGciOi...` with 3 dot-separated base64url segments. Only use `jwt_forge` when an actual valid JWT is issued.
3. **Authenticated Deep Reconnaissance & Surface Expansion:**
   - Once logged in, run `spider` with the acquired session cookie to map the entire authenticated application surface.
   - Use `curl` to fetch and read internal directory, member, user list, profile, and settings pages mapped during recon.
   - Harvest identifiers, roles, contextual profile information, security recovery indicators, and secondary routes before attempting privilege escalation.

---

## 2. Mandatory First Step: Mining Client JavaScript (NO Blind Guessing)

Modern Single-Page Applications (React, Vue, Angular, Next.js) bundle their entire routing and permission logic into client-side JavaScript. **Never guess API endpoints or payload attributes blind — the frontend source code literally contains the application blueprint.**

1. **Discover & Download JavaScript Bundles:**
   - Inspect the HTML source or `discovered_script_assets` returned by `curl` for script bundles (e.g. `/assets/index-*.js`, `/assets/app.js`, `/static/js/main.js`, `bundle.js`).
   - Use `curl` to fetch the referenced `.js` files.
2. **Extract Real API Endpoints & Route Tables:**
   - Search the downloaded JS for API routes (`/api/...`, `routes`, `path:`, `endpoints`).
   - Identify post-login endpoints that aren't visible on the public landing page (e.g., account profile updates, team management, workspace settings, administrative consoles).
3. **Analyze Authorization & Permission Checks:**
   - Search the JS for conditional checks and role evaluations:
     - Keywords: `role`, `admin`, `owner`, `manager`, `permissions`, `is_`, `can_`, `tier`, `entitlements`, `status`, `account_type`.
   - Identify what specific properties or nested object hierarchies the frontend evaluates to unlock privileged UI components or authorize API calls.
   - Note the exact field names discovered (e.g., whether the app checks a top-level property or a nested configuration object).

---

## 3. Deep Mass Assignment & State-Changing APIs

The most prevalent privilege escalation flaw in modern JSON APIs occurs when backend ORMs or object-spread patterns (`{ ...user, ...req.body }`) blindly accept extra fields during profile, account, or settings updates.

### The "Managed Field" Defense vs. Secondary Property Injection

1. **Top-Level Field Lockdown:**
   - When updating a profile (e.g. `PATCH /api/account` or `PUT /api/user`), developers often add an explicit guard against direct changes to the primary role:
     `{"role": "admin"}` → `400 Bad Request: role is a managed field, cannot be updated.`
2. **The Secondary/Nested Property Bypass:**
   - While the primary role field is locked down, developers frequently forget to protect secondary or nested attributes discovered in the JavaScript analysis.
   - By constructing a JSON payload that supplies the exact nested property hierarchy identified in the frontend JS, the server may blindly persist the elevated attribute into the user's database record without triggering the top-level role guard.

### Systematic Verification Sequence:
1. **Locate the True Update Endpoint:** Target the specific account/profile/settings update route identified from the JavaScript reverse-engineering (e.g. `PATCH /api/account`).
2. **Probe with Discovered Schema:** Submit the exact attribute names and structures discovered in the JS.
3. **Verify State Persistence:** Issue a `GET` request to the account/profile endpoint to confirm if the backend persisted the modified attributes.
4. **Access the Protected Console/Resource:** Use the active session to load the privileged endpoint or management portal.

---

## 4. Client-Side Trust vs. Server-Side Trust

Always distinguish between cosmetic UI unlocks and genuine backend privilege escalation:

| Attack Technique | What It Proves | Real Bounty Severity |
|---|---|---|
| **Response Tampering** (Editing API response in proxy/browser) | Proves frontend renders UI based on provided JSON. Does NOT modify backend permissions. | **Informational / Low** (unless backend endpoints fail to validate authorization). |
| **Request Tampering / Mass Assignment** (Sending extra fields in `PATCH`/`POST` that server accepts and persists) | Proves backend ORM/database was mutated to grant real elevated privileges. | **High / Critical** (Full Privilege Escalation / Account Takeover). |

---

## 5. IDOR / Broken Object Reference Strategy

**IDOR isn't only about the object ID being read — check the PARENT/tenant
ID in creation requests too.** A disclosed PayPal report ($10,500 bounty)
found the IDOR not in a resource being fetched, but in the `business_id`
field of a request that CREATES a new sub-account: the endpoint blindly
trusted whatever `business_id` was submitted, so swapping it to a
different organization's ID let the attacker create a fully-privileged
sub-user (fund transfers, refunds, balance access) inside a business
account they didn't own. Any "create X under organization/team/business Y"
endpoint is an IDOR target on the container ID, not just endpoints that
read or update an existing object by its own ID — test swapping the
parent/tenant ID on every creation request, not only the target-object ID
on read/update requests.

1. **Check for Leaked IDs First:** Look for UUIDs, account IDs, or tenant slugs in public profiles, comments, team member lists, or API metadata.
2. **Numeric vs UUID IDs:**
   - Numeric IDs (`1001`, `1002`): Test decrementing/incrementing, especially `0` and `1` (often the system admin or organization owner). Trying a known/likely admin ID directly is a legitimate, low-cost first probe on its own — you don't need a second account to justify it. If it returns real data, apply Section 6's minimal-access discipline (confirm it's real, don't page through more than needed, report) — the same discipline that applies to any other confirmed access.
   - UUIDs: Do not attempt to brute-force; extract real IDs from member lists, invitations, or API responses.
3. **Cross-Tenant Horizontal Confirmation Needs Two Contexts, Not Just Two IDs:**
   - A single ID swap (even a successful one) shows an object reference is guessable/enumerable — it doesn't by itself prove a TENANT boundary is broken, since you need two separate tenant contexts to demonstrate that. For horizontal access specifically (Tenant/Org A reaching Tenant/Org B's records, not just "user A reaching admin"), register or use a second test account in a genuinely different tenant/organization and confirm the swap works from that side too. This is about building a clean, unambiguous, reproducible PoC for the cross-tenant case — not a requirement to gate every ID-guessing attempt behind owning a second account first.
4. **Test All HTTP Verbs on Sibling Endpoints:**
   - If `GET /api/documents/123` is blocked, test `POST /api/documents/123/export`, `PUT /api/documents/123`, or `DELETE /api/documents/123`.

## 5.1 Target Profile IDOR Mining & Token Delegation Chaining (CRITICAL)
1. **Target-Specific Profile & State Extraction (IDOR on Profiles/Data)**:
   - When hunting for a specific target user/role (e.g. user ID 1, Chief of Medicine, Admin):
     * Do NOT only check your own profile or a generic `/users` list.
     * Actively probe object/profile endpoints for the target ID with `curl` (e.g. `GET /profile/1`, `GET /portal/profile/1`, `GET /api/user/1`, `GET /users/1`).
     * Read the response body carefully for embedded secrets, `auth_token`, API keys, MFA seeds, password hashes, or `window.INIT_PROFILE` state objects.
2. **Probe Accessible/Allowed Objects When Target Action is Blocked**:
   - When an action or mutation targeting a privileged entity (e.g. `<endpoint>/<victim_id>/impersonate`) returns `403 Forbidden` or `404 Not Found`, do NOT stop.
   - Test the same action on accessible or normal entities (e.g. `<endpoint>/<allowed_id>/impersonate` or your own account ID) with both `GET` and `POST`.
   - Reverse-engineer the mechanism: Does it reveal a redemption URL or one-time token handler (e.g. `{"hint": "Use at /login/impersonate?token=..."}`)?
3. **Artifact Inventory Cross-Check (Mechanical Field-Name Matching)**:
   - **CRITICAL RULE**: Before searching for a new token or firing new recon, check whether a matching token was already harvested earlier in this session from any staff/user/profile endpoint in the **Harvested Artifact Inventory**.
   - Before constructing a request to any endpoint accepting a parameter matching `token|key|secret|auth|session|sid|delegation`, cross-check every entry in the Harvested Artifact Inventory for a plausible match, regardless of exact field-name spelling. A field named `auth_token`, `access_token`, `delegation_key`, or `cmo_secret` are all candidates for a parameter named `token`. Do not conclude a new token must be found until the existing inventory has been checked.
4. **Autonomous Artifact Chaining (Token Parameter Injection)**:
   - Combine the two primitives: Take the victim's leaked `auth_token` (harvested from the profile IDOR or JS state) and pass it directly to the discovered handler:
     ```json
     {
       "tool": "curl",
       "args": {
         "url": "https://<target>/login/impersonate?token=<victim_harvested_token>",
         "method": "GET"
       }
     }
     ```
   - Capture the newly issued session cookie from `Set-Cookie: session=...` or the returned privileged JWT.
   - Use the newly elevated session to access protected endpoints (`/portal/records`, `/portal/admin`, `/portal/profile`), extract all target flags/proof, capture `gowitness` visual evidence, and record the finding.

## 5.2 403 Forbidden / 401 Unauthorized Perimeter Bypass

If an administrative endpoint, internal API, or sensitive route returns
`403 Forbidden` or `401 Unauthorized` rather than requiring a privilege
you don't have on a resource you CAN reach, that's a perimeter/reverse-
proxy bypass problem, not an access-control-logic problem — use the
`403-bypass` skill (`load_skill("403-bypass")`), which covers path
manipulation, header-based trust spoofing, method override, and the
false-positive discipline specific to that bug class in full depth.

---

## 6. Strict Verification Gate: Eliminating False Positives

Single Page Applications (SPAs) return `HTTP 200 OK` for virtually all routes because the server serves the generic HTML/JS shell. 

**DO NOT assume an exploit succeeded just because an endpoint returns HTTP 200 or an image was captured.**

### Verification Checklist Before Claiming Impact:
- [ ] **Check for Access Denial Screens:** Does the page text, title, or screenshot say `"403"`, `"Owner access required"`, `"Access Denied"`, `"Restricted to workspace owners"`, or redirect to login? If YES, the exploit **FAILED**.
- [ ] **Check for Real Sensitive Data:** Has the application actually returned privileged data?
  - Organization billing secrets, Stripe/payment tokens, API keys
  - Full member directories, email addresses, audit logs
  - Administrative management controls (delete workspace, transfer ownership, edit team)
- [ ] **Check API Response Payloads:** Confirm that API responses return valid JSON data rather than `{ "error": "Unauthorized" }` or `{ "status": 403 }`.

---

## 7. Recording Verified Findings

Once (and ONLY once) you have verified positive backend access with real sensitive data and visual proof:
1. Capture authenticated screenshot of the unlocked console/dashboard with `gowitness`.
2. Record the finding with `record_finding` specifying:
   - `title`: e.g. "Privilege Escalation to Organization Owner via Mass Assignment of Nested Authorization Attributes"
   - `kind`: "mass_assignment" or "privilege_escalation"
   - `severity`: "critical" or "high"
   - `request_ref`: The exact state-changing endpoint and vulnerable payload.
   - `note`: Detail the exact property manipulated and the privileged data unlocked.
3. Produce a structured HackerOne-ready report documenting the root cause, reproduction steps, evidence, and remediation.
