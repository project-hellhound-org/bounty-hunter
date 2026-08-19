---
name: prototype-pollution-mass-assignment
description: Methodology for client/server prototype pollution (JS __proto__/constructor.prototype), mass assignment on JSON APIs, and nested-field privilege escalation via unfiltered object merge/update endpoints.
---

# PROTOTYPE POLLUTION & MASS ASSIGNMENT METHODOLOGY

Execute against ANY endpoint that accepts JSON and merges it into an internal object: settings/preferences updates, profile updates, config endpoints, "update" or "patch" API routes — especially Node.js/Express backends (prototype pollution) and any framework auto-binding request bodies to model objects (mass assignment).

## 1. Map the Target Object's Real Shape First
Do not guess field names. Determine the actual writable surface before testing:
- Read the client-side JS calling the endpoint for the exact JSON shape it sends on a normal request.
- Check any related GET/read endpoint for the full object structure (a `GET /api/profile` response often reveals internal field names like `role`, `entitlements.admin`, `metadata.tier` that the corresponding `POST`/`PATCH` might also accept even if the UI never sets them).
- Note ALL fields visible anywhere, including nested ones — the vulnerable field is often NOT the obvious top-level one (`role`) but a nested sibling (`entitlements.admin`, `metadata.flags.beta`) that received less scrutiny during development.

## 2. Test the Obvious Field First (Expect It to Be Blocked)
```json
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "POST", "json": {"role": "admin"}}}
```
- A clean rejection ("role is a managed field") is a GOOD sign, not a dead end — it confirms the developer specifically thought about THIS field, which means other fields carrying equivalent privilege were probably NOT given the same scrutiny. Proceed to Step 3 immediately rather than concluding the endpoint is safe.

## 3. Test Every Nested Field With Equivalent Privilege
For every alternate field discovered in Step 1 that could plausibly gate the same access:
```json
{"tool": "curl", "args": {"url": "<target_endpoint>", "method": "POST", "json": {"entitlements": {"admin": true}}}}
```
Repeat for every plausible nested path found in client JS or read-endpoint responses. Re-check the account's actual privilege level after EACH attempt (via a protected endpoint or profile re-fetch) — a `200 OK` on the update request does not confirm the field was actually applied or had any effect.

## 4. JavaScript Prototype Pollution (Node.js/Express specifically)
If mass assignment via named fields is fully blocked, test whether the merge logic itself is exploitable via prototype chain traversal:
1. Direct `__proto__` test (often filtered by naive string-match defenses):
```json
{"__proto__": {"polluted": true}}
```
2. If blocked, use the `constructor.prototype` equivalent path — many filters check only for the literal string `__proto__` and miss this identical route to the same object:
```json
{"constructor": {"prototype": {"unlocked": true}}}
```
3. Confirm pollution succeeded by checking whether the injected property now appears on a COMPLETELY UNRELATED object/endpoint elsewhere in the app (true prototype pollution affects every object of that type application-wide, not just the one you posted to) — this is the definitive proof, not just a `200 OK` on the pollution request itself.

## 5. Chain Pollution Into Actual Impact
Prototype pollution alone (an extra property existing on `Object.prototype`) is not automatically a vulnerability — it needs a chain. After confirming pollution in Step 4:
- Test whether any authentication/authorization check in the app reads a property that could plausibly fall back to the polluted prototype default (e.g. an `if (user.isAdmin)` check where `isAdmin` was never explicitly set on the user object, so it inherits from the now-polluted prototype).
- Test whether the polluted property affects rendering (potential DOM XSS via polluted template options) or logic flow (auth bypass, feature unlock) elsewhere in the app.
- Bug bounty programs generally require demonstrated IMPACT, not just proof that pollution occurred — do not report bare prototype pollution without a demonstrated downstream effect unless the program's scope explicitly rewards the primitive alone.

## 6. Verification & Evidence
1. Re-verify actual privilege/state change via an independent authenticated request AFTER the pollution/mass-assignment attempt — never rely on the mutation response alone.
2. Capture the before/after state (privilege level, unlocked feature, visible data) as evidence.
3. Record:
```json
{"tool": "record_finding", "args": {"title": "Privilege Escalation via <Nested Field Mass Assignment / Prototype Pollution>", "kind": "mass_assignment", "severity": "high", "request_ref": "<target_endpoint>", "note": "Top-level field (<name>) was correctly blocked; nested field (<path>) carrying equivalent privilege was not validated server-side. Confirmed via independent re-check of account state post-mutation."}}
```

## Rule of Exhaustion
Blocking the obvious field is a signal to dig deeper, not stop. Enumerate every nested field visible anywhere in the app's own responses or client JS before concluding an update endpoint is properly locked down.
