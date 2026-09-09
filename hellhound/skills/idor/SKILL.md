---
name: idor
description: Full-spectrum methodology for Insecure Direct Object Reference discovery across sequential IDs, GraphQL node references, session-object misbinding, cross-tenant boundaries, and new-feature blind spots. Beginner through professional, grounded in real disclosed HackerOne report patterns.
---

# IDOR (INSECURE DIRECT OBJECT REFERENCE) METHODOLOGY

IDOR is the highest-frequency, highest-impact bug class on HackerOne by report volume. An analysis of 252 top disclosed IDOR reports found the vulnerability collapses into five recurring shapes. The bug is never really about finding an ID, it's about finding where the server forgot to check who that ID actually belongs to.

## 1. The Core Question, Asked of Every Endpoint

For every single request that includes ANY identifier, an ID, a username, an email, a UUID, a slug, an order number, ask exactly one question before moving on: **does the server verify the CURRENT authenticated session actually owns or has explicit rights to this specific object, or does it only verify that a valid session exists at all?** Most IDORs exist because a developer implemented authentication (are you logged in?) correctly but never implemented authorization (are you allowed to touch THIS specific record?) on that particular endpoint.

## 2. Pattern 1 — Sequential/Predictable Identifiers

The classic shape, still the most common in disclosed reports:
1. Perform a normal action as your own account and capture the request (`GET /api/orders/1032`, `?user_id=4471`).
2. Change ONLY the identifier to a nearby value (your ID +1, -1, or a value harvested from anywhere else in the app, a public listing, another user's visible profile, an email you know) while keeping your own session/cookie.
3. Compare the response to what you'd expect if authorization were enforced: a different user's full object (not just a generic error) confirms the bug.
4. **Test both read AND write operations separately** — an endpoint might correctly block you from viewing another user's object but still accept a `PUT`/`PATCH`/`DELETE` against that same ID (this exact asymmetry is how Reddit's "modify any user's links" and multiple "delete X" IDORs were found — deletion/modification endpoints are frequently checked less carefully than the corresponding read endpoint).

```json
{"tool": "curl", "args": {"url": "<endpoint>?id=<other_user_id>", "method": "GET", "headers": {"Cookie": "<your_own_session>"}}}
```

## 3. Pattern 2 — GraphQL Node Substitution

Modern APIs built on GraphQL replace REST's obvious `?id=` parameter with an opaque global `node` ID, which developers sometimes mistake for a security boundary. It isn't, encoding is not authorization:
1. Capture any GraphQL query/mutation returning or accepting a `node(id: "...")` or object-type-specific ID.
2. Base64-decode the node ID if it looks encoded, GraphQL node IDs are frequently just `base64("Type:12345")`, meaning you can construct a target ID by re-encoding a different numeric value for the same type.
3. Substitute a different decoded/re-encoded ID into the SAME query or mutation using your own session token.
4. This exact pattern produced real disclosed findings: HackerOne's own "Delete Licenses and certifications using CreateOrUpdateHackerCertification GraphQL query" and Shopify's "Stored XSS in product description via productUpdate GraphQL query" both hinge on a mutation accepting an ID it should have scoped to the caller's own resources.

## 4. Pattern 3 — Session-Object Misbinding

The subtler pattern: the object reference isn't in the URL or body at all, it's implicitly derived from something in the session that itself can be manipulated:
1. Look for object references embedded in a JWT, a hidden form field, a cookie value, or a "resume where you left off" token, rather than an explicit URL parameter.
2. Test whether changing that embedded reference (forging a JWT claim, editing a hidden field, swapping a resume token) changes which object the server acts on, even while every OTHER part of your session stays your own.
3. This is the shape behind account-takeover-via-IDOR chains — CrowdSignal's "IDOR when editing users leads to Account Takeover without User Interaction" and Starbucks' "Account Takeover via IDOR" both involved an edit/update flow where the target-user reference could be substituted independent of the actor's own authenticated identity.

## 5. Pattern 4 — Cross-Tenant Boundary Failures

In multi-tenant SaaS apps (organizations, workspaces, teams, stores), IDOR often isn't about individual USER records, it's about crossing the ORGANIZATION boundary entirely:
1. Create or use two separate tenant accounts if the target allows self-signup (a free trial, a demo workspace).
2. Identify any endpoint scoped to "your" organization/workspace/store (`/api/org/<org_id>/settings`, `/api/workspace/<ws_id>/members`) and substitute the OTHER tenant's org/workspace ID.
3. This produced some of the highest-value disclosed reports precisely because impact scales with the number of OTHER tenants exposed, not just one user: Shopify's "partners.shopify.com — user with ONLY Manage apps permission is able to get shops info and staff names from inside the shop" and Nord Security's "IDOR allow access to payments data of any user" both hinge on a tenant-scoping check that existed for the UI navigation but not for the underlying API call.
4. Pay specific attention to any endpoint reachable with a LOWER permission tier than the data it returns (a "manage apps only" role reaching full shop staff data) — permission-tier mismatches inside a single tenant are a variant of this same boundary failure.

## 6. Pattern 5 — New-Feature Blind Spots

The newest, least-tested part of any application is statistically the most likely place to find IDOR, because authorization logic that's been hardened over years on the core product frequently isn't ported correctly to a feature that shipped last month:
1. Actively look for beta features, "unreleased," recently-announced, or clearly newer UI sections (different design language, a "New!" badge, a separate subdomain like `beta.` or `new.`).
2. HackerOne's own "IDOR vulnerability in unreleased HackerOne Copilot feature" is the textbook example, brand-new functionality, same underlying user/org model as the mature product, but the authorization check hadn't caught up yet.
3. Any newly-launched AI/chatbot feature, new dashboard redesign, or beta-flagged API version deserves a full independent pass through Patterns 1-4 rather than assuming the app's overall security posture applies uniformly.

## 7. Blind IDOR

Some IDORs leak nothing visible in the direct response, the confirmation only comes through a side channel:
1. If a suspected IDOR request returns a generic success/error regardless of whether the target ID is valid, don't conclude the endpoint is safe purely from the response body.
2. Check for out-of-band confirmation instead: does the action trigger an email/notification you can observe (even to a test account you control, comparing behavior across two IDs), does it change a COUNT you can observe elsewhere (a "views" or "likes" counter incrementing), or does a subsequent legitimate request reveal the side effect (an item now appearing deleted/modified when re-fetched through a proper channel)?
3. Blind IDOR against a write/delete endpoint is often MORE dangerous than a readable one, since an attacker can silently corrupt or delete other users' data with zero visible confirmation to either party until later.

## 8. Verification & Evidence

1. A single successful cross-ID request is a lead, not a confirmed finding, repeat against at least one additional distinct ID to rule out a coincidental misconfiguration on one specific record.
2. Capture BOTH requests side by side in the report: your own object (proving the normal/expected response shape) and the foreign object (proving unauthorized access), not just the second one alone.
3. For write/delete IDORs, always test on your OWN secondary test account or a disposable object first, never a live third party's real data, when a program's scope allows creating throwaway test resources.
4. Record:
```json
{"tool": "record_finding", "args": {"title": "IDOR via <endpoint> Allowing Unauthorized <Read/Write/Delete> of Other Users'/Tenants' Data", "kind": "idor", "severity": "high", "request_ref": "<endpoint>", "note": "Own-object request and foreign-object request compared side by side. Pattern: <sequential ID / GraphQL node / session misbinding / cross-tenant / new-feature>. Confirmed via <direct response / blind side-channel>."}}
```

## 9. Impact Framing

Severity scales with WHAT the exposed object is and HOW MANY objects are reachable, not just that unauthorized access occurred at all:
- A single user's non-sensitive preference setting exposed via IDOR is low severity.
- Payment data, private messages, authentication credentials, or any cross-TENANT exposure (reaching an entire other organization's data, not just one user) scales toward critical, especially when the ID space is small enough or predictable enough to enumerate at scale (sequential integers spanning an entire user base turns a single-record bug into a mass-disclosure one).
- Always state in the report whether the identifier space is enumerable in bulk (sequential integers) or requires per-target guessing (random UUIDs, only exploitable if the ID was leaked elsewhere first) — this materially changes real-world exploitability and expected severity.

## Rule of Exhaustion
Don't stop at the first endpoint that correctly blocks cross-ID access. Test read AND write operations separately (Pattern 1), check every GraphQL mutation touching an object type you've already confirmed is sensitive (Pattern 2), look for the object reference hiding in a token/cookie instead of the URL (Pattern 3), test across tenant boundaries wherever multi-org structure exists (Pattern 4), and always give newly-shipped features a full independent pass (Pattern 5) rather than assuming the rest of the app's authorization discipline carried over.