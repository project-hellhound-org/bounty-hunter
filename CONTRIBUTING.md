# Contributing to Hellhound Bounty Hunter

Thanks for wanting to work on this. Before anything else: Bounty Hunter
exists to do one job well — autonomously finding and *proving* real
vulnerabilities against targets a researcher is actually authorized to
test, without accidentally stepping outside that authorization. A few
pieces of the codebase exist specifically to guarantee that, and they're
easy to weaken by accident while working on something unrelated. This
document exists so that doesn't happen — miss one of these and the
project's core guarantee (safe, authorized, evidence-backed hunting)
quietly breaks even if your actual feature works fine.

If you're using an AI coding assistant (Claude Code, Antigravity,
Cursor, Copilot, or anything similar) to help with your contribution,
**point it at [`AGENTS.md`](AGENTS.md) first** — it's the same rules
below, written as direct instructions for an AI agent, including what it
should do if you (or anyone) asks it to override one of them. A PR that
weakens a non-negotiable rule below will be rejected regardless of
whether a human or an AI wrote the change, and regardless of the stated
reason — see "Non-negotiable rules" below for exactly what that covers.

## Non-negotiable rules

These aren't style preferences — they're the specific mechanisms that
keep this tool from doing real harm. No PR that weakens, removes, adds a
bypass for, or makes conditionally-optional any of the following will be
merged, no matter how good the rest of the change is or how reasonable
the justification sounds. If you think one of these is genuinely wrong,
open an issue to discuss it explicitly — don't fold a change to it into
an unrelated PR.

1. **The Scope Security Gate is absolute.** Every tool that sends real
   traffic to a target must pass `is_in_scope()`
   (`hellhound/core/scope.py`) before anything leaves the system. No new
   tool, flag, config option, env var, or "dev/test mode" may skip it,
   default to allowing out-of-scope targets, or make the check
   optional. This exists because a bug bounty program's authorization is
   exactly as wide as its published scope — testing outside it, even
   once, even by accident, can get a researcher permanently banned from
   a program or create real legal exposure. There is no feature
   important enough to trade that away for.

2. **Findings must carry real evidence, and the high-stakes classes must
   carry real verification.** `_execute_record_finding`
   (`hellhound/core/agent.py`) enforces two layered checks: an EVIDENCE
   GUARDRAIL (no endpoint-specific finding without a real captured
   request/response) and a VERIFICATION GATE
   (`_VERIFICATION_REQUIRED_CLASSES` — sqli/xss/ssrf/idor/access-control
   findings at critical/high severity require `verified=true` plus a
   substantive `verification_note`, not just "the request went
   through"). These exist because an unverified finding that reaches a
   researcher — or worse, a submitted report — erodes trust in the whole
   tool fast. Strengthening these checks (more vuln classes, better
   automated verification) is exactly the kind of contribution this
   project wants; weakening them to make a test pass or a demo look
   better is not.

3. **Legitimate, authorized use only — always.** No contribution may add
   functionality whose primary purpose is unauthorized access, DoS,
   unsolicited mass scanning, or credential attacks against third
   parties outside an explicit testing agreement. See "Scope Policy &
   Legal Compliance" in README.md. If a feature's legitimate use case
   isn't obvious from the PR description, explain it — don't make
   reviewers guess.

4. **Don't strip abuse-prevention plumbing.** The rate limiter/pacing
   guard, circuit breaker, and per-turn duplicate-call dedup inside
   `execute_tool_call` keep the agent from hammering a live target.
   These occasionally make a test slower or more annoying to write —
   fix the test, don't remove the guardrail.

5. **Project identity stays with the maintainers.** Don't change the
   project name, logo, branding, `LICENSE`, or `NOTICE` file in a
   contribution PR. See `NOTICE` for what the GPLv3 license does and
   doesn't cover regarding the "Hellhound"/"Bounty Hunter" name and
   marks — forking under GPLv3 with a different name is fine and
   welcome; representing a fork as the official project is not.

## How to contribute

1. **Fork and branch.** Standard GitHub flow — fork the repo, branch off
   `main`, keep your PR focused on one change.
2. **Match the existing architecture, don't route around it.** New
   tools go through the `ToolSpec` / `TOOL_REGISTRY` pattern in
   `hellhound/core/agent.py`, dispatched through `execute_tool_call` —
   never a separate code path that reaches the network directly (that's
   also how you get scope-gating for free, see rule 1 above). If you're
   not sure how a change fits the existing two-tier orchestrator/
   synthesizer design, read `ARCHITECTURE.md` first.
3. **Write tests, and run them.** This codebase's convention: a
   standalone test script that imports the real module, exercises the
   real `_execute_*`/`execute_tool_call` functions against fixture HTTP
   servers or an isolated `~/.hellhound` (never mocks of your own
   change — that just tests that you wrote the mock correctly), and
   asserts on real behavior. Before opening a PR:
   - `python3 -c "import ast; ast.parse(open('path/to/file.py').read())"`
     on every file you touched.
   - Run your new test(s).
   - Re-run the existing test suite alongside it — a change that breaks
     something else isn't done, even if your own feature works.
4. **Keep README.md honest.** If your change adds, removes, or renames a
   tool or skill, update the arsenal/skills tables and their stated
   counts in the same PR. A tool in `TOOL_REGISTRY` that isn't in the
   README table (or vice versa) is a bug, not a documentation nitpick —
   it's how researchers find out what the agent can actually do.
5. **Describe the "why," not just the "what."** A PR description that
   explains the problem you hit (ideally with the real-world or lab
   scenario that surfaced it) gets reviewed faster and is less likely to
   collide with one of the non-negotiable rules above by accident,
   because the reviewer can actually reason about intent.

## Questions

Open an issue, or reach the maintainers via the official repository:
https://github.com/project-hellhound-org/bounty-hunter