---
name: race-condition
description: Methodology for identifying and exploiting race conditions (TOCTOU) in rate-limited actions, one-time claims, balance/inventory operations, and coupon/discount redemption endpoints.
---

# RACE CONDITION METHODOLOGY

Execute against ANY endpoint that enforces a "this can only happen once" or "this can only happen N times" rule server-side: daily reward claims, coupon redemption, balance transfers, inventory purchase, password reset attempts, vote/like actions, referral bonus claims.

## 1. Identify the Two-Step Pattern First
Race conditions exist because "check" and "act" are two separate steps instead of one atomic operation. Before firing parallel requests, confirm this pattern is plausible:
- Does the endpoint's response or client JS reference a "can I do this" state separate from "doing this" (e.g. a `canClaim: true/false` field, an `alreadyRedeemed` flag checked before the action executes)?
- Is the underlying action a multi-step DB operation (read balance → check threshold → write new balance) rather than a single atomic increment? Multi-step logic is far more likely to have a timing gap than a single `UPDATE ... SET x = x + 1` query.
- If the backend language/framework is known, note whether it commonly uses ORMs with separate read-then-write patterns (common in Node.js/Express + Mongoose or Python/Flask + SQLAlchemy without explicit atomic operations) — this raises the likelihood of a real gap.

## 2. Confirm Normal Single-Request Behavior First
Before racing, use the endpoint normally once and read the FULL response carefully:
```json
{"tool": "curl", "args": {"url": "<target_action_endpoint>", "method": "POST"}}
```
- Note the exact fields returned (new balance, remaining count, timestamp, rate-limit metadata like `secondsUntilNextClaim`).
- Immediately repeat the SAME request sequentially (not in parallel) to confirm the rate limit/one-time rule is enforced under normal conditions — if it isn't even enforced sequentially, this isn't a race condition, it's a straightforward broken access control bug requiring no timing attack at all.

## 3. Fire the Actual Race
Send a burst of identical requests as close to simultaneously as possible — sequential requests (even fast ones) will NOT reproduce a race condition; true concurrency is required:
```json
{"tool": "race_requests", "args": {"url": "<target_action_endpoint>", "method": "POST", "headers": {"Cookie": "<session_cookie>"}, "count": 20, "concurrency": 20}}
```
If a dedicated concurrent-request tool isn't available, use a proxy's built-in concurrent-repeater feature (e.g. Burp/Caido "send group in parallel") rather than a manually scripted loop, since network-stack request queuing in a simple loop often serializes requests enough to miss the window.

## 4. Analyze Results for Multiple Successful Executions
After the burst, check the resulting state (balance, redemption count, claimed flag) via an independent read request:
- If the final state reflects MORE than one successful execution (e.g. balance increased by 3x the single-claim amount, or a coupon was redeemed twice), the race condition is confirmed.
- If only one request succeeded and the rest were rejected, increase concurrency count and retry 2-3 times before concluding the endpoint is properly locked (network jitter can mask a real race on the first attempt).

## 5. Widen the Race Window (If Initial Burst Fails)
If a straightforward burst doesn't produce multiple successes:
- Look for a way to artificially slow down the "check" step relative to the "write" step — e.g. submitting a large payload in the same request if the endpoint processes input before the balance check, which can widen the exploitable window.
- Try racing against a DIFFERENT but related endpoint that shares the same underlying state (e.g. racing a "claim" endpoint against a "transfer" endpoint if both touch the same balance field) — some race conditions only appear across two related operations, not the same one repeated.

## 6. Verification & Evidence
1. The state change must be independently re-verified via a separate authenticated read AFTER the race burst — never trust the individual response bodies from the parallel requests alone, since some may show stale/cached data.
2. Capture the before-race and after-race state side by side as the core evidence (e.g. balance: 0 → 500 after 20 parallel claims of 50 each, when only ONE claim should have succeeded).
3. Record:
```json
{"tool": "record_finding", "args": {"title": "Race Condition in <Action Name> Enabling Multiple Executions of Rate-Limited Action", "kind": "race_condition", "severity": "high", "request_ref": "<target_action_endpoint>", "note": "Fired <N> concurrent requests; <M> succeeded when only 1 should have. Before state: <X>. After state: <Y>."}}
```

## Rule of Exhaustion
A single failed burst attempt does not rule out a race condition — retry with higher concurrency, and if the endpoint still holds, test related endpoints touching the same underlying state (Step 5) before concluding the operation is properly atomic.
