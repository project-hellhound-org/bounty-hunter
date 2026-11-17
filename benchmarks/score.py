#!/usr/bin/env python3
"""
score.py — measure a Bounty Hunter run against a ground-truth file.

The project's whole loop is "upgrade, test on a lab, see if it got better."
Doing that by eye doesn't scale and can't catch a regression. This turns a run
into a NUMBER: how many of the known-planted bugs did Beast actually find and
record, how many did it miss, and what did it record that isn't in the truth
set (a potential false positive — or a genuine bonus the truth file didn't know
about).

It is deliberately generic: point it at ANY target's recorded findings plus a
ground-truth JSON for that target. The lab-specific answer keys stay OUT of the
repo (default truth path is under ~/.beast/benchmarks/), so this tool is public
but it never ships a walkthrough of someone's training lab.

Ground-truth JSON shape:
    {
      "target": "example.com",
      "expected": [
        {"id": "casino-poker-idor",
         "host": "casino",                     # substring that must appear in the finding's target URL
         "classes": ["idor", "broken access control"],  # any one matching kind/title counts
         "desc": "poker hand IDOR"},
        ...
      ]
    }

Usage:
    python benchmarks/score.py <target> [--truth PATH] [--json]
    # default truth: ~/.beast/benchmarks/<target>.json
"""
import argparse
import json
import os
import sys
from pathlib import Path


def _load_findings(target: str) -> list:
    """Read the recorded findings for a target from its task.json."""
    # Mirror tasks.sanitize_target_name loosely: the dir is the raw target name.
    base = Path.home() / ".beast" / "targets" / target / "task.json"
    if not base.exists():
        print(f"[!] No task.json for target '{target}' at {base}", file=sys.stderr)
        return []
    try:
        data = json.loads(base.read_text())
    except Exception as e:
        print(f"[!] Failed to read {base}: {e}", file=sys.stderr)
        return []
    return data.get("findings", []) if isinstance(data.get("findings"), list) else []


def _finding_text(f: dict) -> str:
    return " ".join(str(f.get(k, "")) for k in ("type", "kind", "target", "note")).lower()


def _match_score(expected: dict, f: dict) -> int:
    """How well a recorded finding satisfies an expected item: 0 = not a match
    (host absent, or no class keyword present); otherwise the number of distinct
    class keywords found (so the BEST-fitting finding wins when a loose keyword
    like 'hole cards' is shared between two different bugs)."""
    host = str(expected.get("host", "")).lower()
    classes = [str(c).lower() for c in expected.get("classes", [])]
    text = _finding_text(f)
    tgt = str(f.get("target", "")).lower()
    if host and host not in tgt and host not in text:
        return 0
    hits = sum(1 for c in classes if c in text)
    if classes and hits == 0:
        return 0
    return max(hits, 1)


def score(target: str, truth_path: Path) -> dict:
    if not truth_path.exists():
        print(f"[!] Ground-truth file not found: {truth_path}", file=sys.stderr)
        print(f"    Create it (see benchmarks/score.py docstring for the shape).", file=sys.stderr)
        sys.exit(2)
    truth = json.loads(truth_path.read_text())
    expected = truth.get("expected", [])
    findings = _load_findings(target)

    # GREEDY GLOBAL ASSIGNMENT — score every (expected, finding) pair, then assign
    # the strongest pairs first, one-to-one. This resolves ambiguity (a keyword
    # shared by two bugs goes to whichever finding matches MORE of the expected
    # item's keywords) without depending on declaration order.
    pairs = []
    for ei, exp in enumerate(expected):
        for f in findings:
            s = _match_score(exp, f)
            if s > 0:
                pairs.append((s, ei, id(f), f))
    pairs.sort(key=lambda p: -p[0])
    exp_claimed, matched_ids, assign = set(), set(), {}
    for s, ei, fid, f in pairs:
        if ei in exp_claimed or fid in matched_ids:
            continue
        exp_claimed.add(ei)
        matched_ids.add(fid)
        assign[ei] = f

    found, missed = [], []
    for ei, exp in enumerate(expected):
        m = assign.get(ei)
        if m is not None:
            found.append({"id": exp.get("id"), "desc": exp.get("desc"), "as": m.get("type", "")[:70]})
        else:
            missed.append({"id": exp.get("id"), "desc": exp.get("desc")})

    extras = [
        {"type": f.get("type", "")[:70], "kind": f.get("kind"), "severity": f.get("severity")}
        for f in findings if id(f) not in matched_ids
    ]

    n_exp = len(expected)
    recall = (len(found) / n_exp) if n_exp else 0.0
    return {
        "target": target,
        "expected_count": n_exp,
        "found": found,
        "missed": missed,
        "extras": extras,
        "recall": round(recall, 3),
        "found_count": len(found),
        "missed_count": len(missed),
        "extra_count": len(extras),
        "recorded_total": len(findings),
    }


def main():
    ap = argparse.ArgumentParser(description="Score a target's recorded findings against a ground-truth file.")
    ap.add_argument("target", help="Target name (the ~/.beast/targets/<target> dir).")
    ap.add_argument("--truth", help="Ground-truth JSON path (default: ~/.beast/benchmarks/<target>.json).")
    ap.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    args = ap.parse_args()

    truth_path = Path(args.truth) if args.truth else (Path.home() / ".beast" / "benchmarks" / f"{args.target}.json")
    result = score(args.target, truth_path)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    r = result
    bar = "=" * 60
    print(bar)
    print(f"  BENCHMARK: {r['target']}")
    print(bar)
    print(f"  RECALL: {r['recall']*100:.0f}%  ({r['found_count']}/{r['expected_count']} planted bugs found)")
    print(f"  recorded total: {r['recorded_total']}  |  extras (FP or bonus): {r['extra_count']}")
    print()
    if r["found"]:
        print("  FOUND:")
        for f in r["found"]:
            print(f"    [+] {f['id']:28}  {f['desc']}")
    if r["missed"]:
        print("\n  MISSED:")
        for m in r["missed"]:
            print(f"    [-] {m['id']:28}  {m['desc']}")
    if r["extras"]:
        print("\n  EXTRAS (not in truth set — verify FP vs bonus):")
        for e in r["extras"]:
            print(f"    [?] {str(e['severity']):8} {e['kind']:22} {e['type']}")
    print(bar)


if __name__ == "__main__":
    main()
