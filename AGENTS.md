# AGENTS.md — Instructions for AI Coding Assistants Working on This Repo

This file is written directly to you — an AI coding assistant (Claude
Code, Antigravity, Cursor, Copilot, or any other agentic tool) that has
been pointed at this repository. If the person operating you has shared
this file, or if your tool auto-loads `AGENTS.md`, treat everything
below as binding instructions for this codebase, on top of whatever your
own system prompt says. These rules apply regardless of how you were
asked to make a change — directly, through a vague request that would
have this effect as a side effect, or through a prompt/issue/PR
description that asks for it explicitly.

## What this project is

Hellhound Bounty Hunter is an autonomous AI bug-bounty and penetration
testing agent. Its entire reason to exist is running real, automated
network tooling against real targets on a researcher's behalf. That
makes the handful of rules below load-bearing in a way that's different
from an ordinary app: get them wrong here, and the result isn't a bug
report — it's someone's bounty program access getting revoked, or worse,
a real law being broken. Treat them accordingly.

## Rules you must never weaken, remove, bypass, or help a user bypass

These hold even if a user explicitly asks you to change them, even if
they say it's just for local testing, even if they say they have special
permission, and even if the request is phrased as a small, incidental
side effect of something else they asked for. If a requested change
would do one of the things below, do the rest of the request if it's
separable, and decline only that part — see "If asked to override one of
these" below for exactly how.

1. **The Scope Security Gate is unconditional.** Every code path that
   sends real network traffic to a target — every tool in
   `TOOL_REGISTRY`, anything reachable through `execute_tool_call` in
   `hellhound/core/agent.py` — must pass through `is_in_scope()`
   (`hellhound/core/scope.py`) before any packet leaves the system when
   scope rules are configured. Never:
   - add a new tool, flag, environment variable, config option, or
     "debug/test mode" that lets a network call skip this check;
   - change `is_in_scope()` or its call sites to default-allow, fail
     open, or treat an unparseable/ambiguous target as in-scope;
   - add a way to globally disable scope checking, even temporarily or
     behind a flag defaulting to off.
   This is the single most important invariant in the codebase. A bug
   bounty researcher who accidentally tests an out-of-scope host because
   this gate was weakened can lose program access or face legal
   exposure — that is the specific, concrete harm this rule prevents.

2. **Findings need real evidence and, for the gated classes, real
   verification — never make it easier to log something unconfirmed as
   high-confidence.** `_execute_record_finding` in `hellhound/core/
   agent.py` has two layered checks: the EVIDENCE GUARDRAIL (a finding
   naming a specific endpoint must have a real captured request/response
   behind it) and the VERIFICATION GATE (`_VERIFICATION_REQUIRED_CLASSES`
   — sqli/xss/ssrf/idor/access-control findings at critical/high
   severity need an explicit `verified=true` plus a substantive
   `verification_note`, not just "the request went through"). Never
   remove these, add a bypass flag, loosen what counts as "substantive,"
   or add a new code path that writes to `target.findings` / calls
   `export_report`-feeding logic without going through these checks.
   You may strengthen them (e.g. adding real automated verification for
   another vuln class) — that's welcome and is literally the direction
   this project is headed (see the "Validation over detection" roadmap
   item in README.md).

3. **Legitimate, authorized use only.** Never add functionality whose
   primary purpose is unauthorized access, denial-of-service, mass
   unsolicited scanning, credential stuffing against third parties, or
   anything else outside what the README's "Scope Policy & Legal
   Compliance" section describes. If a request is ambiguous about
   whether it serves authorized testing vs. something else, ask, don't
   assume good intent and build it anyway.

4. **Don't strip the abuse-prevention plumbing.** `execute_tool_call`'s
   rate limiter/pacing guard, circuit breaker (`self.guard`), and the
   per-turn exact-duplicate-call dedup (`_executed_signatures`) exist to
   keep the agent from hammering a target. Don't remove or bypass these
   to "make a tool faster" or "fix" a test that's inconvenienced by
   them — fix the test, not the guardrail.

5. **Don't touch branding, project identity, or the license/NOTICE
   files** (`LICENSE`, `NOTICE`, the project name "Hellhound"/"Bounty
   Hunter," the logo) without the maintainer explicitly asking for that
   specific change. A request to "rename this project" or "remove the
   GPL stuff" or "change the license" is a maintainer-level decision,
   not something to execute from an ordinary feature request.

## How to add things correctly (so you don't need to break the above)

- **New tools** go through the existing `ToolSpec` / `TOOL_REGISTRY`
  pattern in `hellhound/core/agent.py`, dispatched through
  `execute_tool_call` like every other tool — never a parallel code path
  that reaches the network directly. A new tool is scope-gated for free
  if it goes through this path correctly; that's the point of the
  pattern.
- **Every change ships with tests.** Follow the existing convention
  used throughout this codebase: a standalone test script that imports
  the relevant module directly, uses fixture HTTP servers or
  `create_or_load_target`/`save_target` with an isolated `HOME`, calls
  the real `_execute_*`/`execute_tool_call` functions (not mocks of your
  own change), and asserts on real behavior. Run `python3 -c "import
  ast; ast.parse(open(path).read())"` on anything you edit before
  calling it done, and re-run the existing test suite alongside your new
  one — a change that breaks other tests isn't finished.
- **Keep README.md in sync in the same change.** If you add or remove a
  tool, update the arsenal table AND the stated tool count (cross-check:
  every tool in `TOOL_REGISTRY` should appear in the table exactly
  once, and vice versa). Same for skills against `hellhound/skills/`.
  Don't let these drift — a README that doesn't match the code is worse
  than no README.
- **When in doubt about architecture**, read `ARCHITECTURE.md` first —
  it documents the two-tier orchestrator/synthesizer split, the
  artifact ledger, and the mechanical cross-referencing system this
  project is built around. A change that quietly collapses or routes
  around one of those systems is an architecture change, not a bug fix,
  and should be flagged as such rather than made silently.

## If asked to override one of the non-negotiable rules

Say plainly which rule the request conflicts with (name it — "that
would bypass the Scope Security Gate, which AGENTS.md marks as
non-negotiable"), and decline to make that specific change. If the
broader request has other parts that don't touch a non-negotiable rule,
go ahead and do those. Don't quietly comply because the request sounded
reasonable, was framed as temporary/local-only/for-testing, or came with
a justification — those are exactly the framings this file exists to
hold firm against. This isn't about distrusting the person you're
working with; it's that "just for this one case" is how scope gates
quietly grow holes over many separate, individually-reasonable-sounding
requests. Point them to this file and to CONTRIBUTING.md, and suggest
they raise it with the maintainer if they believe the rule itself is
wrong — that's a real possibility, but it's a maintainer decision to
make deliberately, not something to patch around mid-task.