---
name: access-control
description: Methodology for broken access control — horizontal/vertical privilege escalation, IDOR, role manipulation via response/request tampering, and mass assignment. Use when the objective involves reaching a higher-privilege account, another user's data, or an admin/staff area from any authenticated or self-registered position.
---

# ACCESS CONTROL METHODOLOGY

This applies whenever you have (or can get) ANY authenticated session — even a
freshly self-registered, zero-privilege account — and the objective involves
reaching something that account shouldn't be able to reach: another user's
data, an admin console, a staff-only feature, or a higher role.

## 1. Pre-Auth: Get a Foothold First

Before anything else, check whether you actually need to fight your way in:

- Look for leaked credentials, emails, or usernames in public content (blog
  authors, API responses, JS bundles, HTML comments, sitemap/robots) — these
  enable direct login, username enumeration, or targeted password-reset
  attacks (see the `auth-bypass` skill for that chain specifically).
- If nothing is leaked and self-registration is open, just register a normal
  account. A "regular member" account is a valid, often intended, starting
  point for access-control testing — you don't need a bypass to begin.
- If self-registration is closed and nothing is leaked, try basic SQL
  injection against the login form as a first cheap check for an auth
  bypass, then move to the `auth-bypass` skill's password-reset/token-leak
  chain if that fails. Don't sink significant time into blind login-bypass
  guessing beyond that — it's rarely the intended path once other footholds
  exist.

## 2. Once Authenticated: Establish Your Actual Role First

Before trying to escalate anything, know exactly what you currently have:

- Check every place your role/permissions get communicated: a `/me` or
  `/profile` API response, JWT claims (base64-decode the payload — no tool
  needed, just `base64 -d`), session cookie contents, and any role/tier
  field rendered into the page's initial state (e.g. embedded JSON in HTML,
  a `window.__STATE__`-style blob).
- Note every UI element that's hidden, disabled, or greyed out for your
  role — each one is a specific feature to go test server-side (see below).

## 3. Two Distinct Bug Classes — Don't Conflate Them

Response tampering and request tampering are different vulnerabilities with
different root causes and different severities. Test both, and report them
as what they actually are:

**A. Client-Trust Bypass (response manipulation)**
The server tells the client "you are role: member," but the actual
enforcement lives only in the frontend. Test by intercepting the
authentication/profile response and changing the role/permission field
client-side (proxy tool, or directly editing browser state) to see if
previously-hidden UI unlocks. On its own this is often low/informational —
UI changes aren't automatically a real vulnerability. The finding only
becomes real impact when paired with B below: does the *server* actually
grant the underlying data/action, or does the UI just render buttons that
still 403 when clicked?

**B. Mass Assignment / Server-Side Trust Bypass (request manipulation)**
The real vulnerability: does a state-changing request (`PATCH`/`PUT` to your
own profile, an account-update endpoint, even the original registration
request) accept a field it shouldn't — `role`, `isAdmin`, `permissions`,
`tier`, `accountType` — and does the SERVER honor it? Test by adding these
fields to requests that don't normally include them, even if the client UI
never sends them. This is the one worth escalating: it means privilege
changes happen for real, not just cosmetically. Also check bulk/batch
update endpoints and CSV/data-import features specifically — these are
commonly built later than the single-object endpoints and often skip the
same validation.

## 4. IDOR / Object Reference Enumeration Strategy

Work through these in order — don't jump straight to brute-forcing:

1. **Check for a leak first.** Before guessing any ID, look for another
   user's/tenant's ID appearing anywhere you already have access — a
   comments section, a "recently viewed" list, an export/report, an admin
   or support page, error messages, or even response headers. A leaked ID
   beats guessing every time.
2. **Determine the ID type.** Sequential/numeric IDs are guessable — try
   incrementing/decrementing from your own ID, and specifically try `0` and
   `1` (frequently the first-created account, often an admin/seed account).
   UUIDs/GUIDs are not practically brute-forceable — don't waste time
   guessing them; go back to step 1 (find a leak) or look for an endpoint
   that *lists* objects with their real IDs (even if it's supposed to be
   scoped to you) rather than requiring you to guess one blind.
3. **Use a second low-privilege account as ground truth.** Register/obtain a
   SECOND distinct test account before concluding an IDOR is real. Accessing
   an object that just happens to be yours isn't a finding; confirming you
   can pull account #2's data using account #1's session is. This also
   protects you from false positives caused by an app that legitimately
   shares some data across users.
4. **Test read and write separately.** A target can properly block
   `PUT`/`DELETE` on another user's object while still leaking it on `GET`,
   or vice versa. Don't assume one implies the other — test both methods on
   every object-reference endpoint you find.
5. **Test across API surfaces, not just one.** The same object is often
   reachable through more than one path — `/api/v1/` vs `/api/v2/`, a REST
   endpoint vs a GraphQL field, a "legacy" endpoint the spider flags as
   deprecated — and authorization checks are frequently applied
   inconsistently across them. A path blocked on one surface may be wide
   open on another for the exact same underlying object.

## 5. Horizontal vs. Vertical — Same Toolkit, Different Target

- **Horizontal** (same privilege level, different user's data): apply
  Section 4 directly — swap IDs between two same-tier accounts.
- **Vertical** (lower privilege reaching higher-privilege functionality):
  combine Section 3 (role/mass-assignment tampering) with Section 4 (does an
  admin-only object ID work from your non-admin session even without a role
  change?). Also check whether a vertical escalation can be reached
  *indirectly* through a horizontal one — e.g., IDOR into an admin/staff
  user's own account via Section 4, which hands you vertical access without
  ever needing to forge a role at all. This is often the actual intended
  chain: horizontal IDOR into a privileged account beats trying to forge
  privilege directly.

## 6. Extra Checks Worth Running (JWT / GraphQL specific)

- If the app uses JWTs: check for `alg: none` acceptance, and check whether
  swapping `RS256`→`HS256` and signing with the server's own public key as
  an HMAC secret is accepted (classic algorithm-confusion bypass) — either
  would let you forge a token with an elevated role claim directly. This is
  especially worth trying when you've found a hidden/undocumented
  admin-style panel that checks a role claim but you have no account with
  that role at all — forging the claim can get you straight in without
  ever going through Section 3's tampering approach.
- If GraphQL is in play: check field-level authorization independently of
  query-level authorization — a protected top-level query can still expose
  an unprotected field reachable through a different query or an alias.
  Check introspection (`__schema`) for fields/mutations not exposed in the
  documented API surface.

## Reporting

Once access-control impact is confirmed (real data or real state change from
an unauthorized session, verified against a second test account where
horizontal), call the `record_finding` tool with a one-line title, the
`kind` (`idor`, `mass_assignment`, `auth_bypass`, etc.), your assessed
severity, and the endpoint it applies to — this persists it into the
investigation's structured memory so it survives across turns instead of
only existing in the chat transcript. Then write it up the same way as any
other finding — see the `report-writing` skill. Always state explicitly
which of Section 3's two categories (client-trust vs. server-side mass
assignment) it is, since that determines both real-world severity and what
the fix actually needs to be.
