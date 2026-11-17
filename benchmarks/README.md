# Benchmarks

Turn a Bounty Hunter run into a **number** instead of eyeballing it. The project's
loop is "upgrade → test on a lab → did it get better?" — `score.py` makes that
measurable and catches regressions a manual read would miss.

## What it does

`score.py` compares the findings Beast has **recorded** for a target (from
`~/.beast/targets/<target>/task.json`) against a **ground-truth** file for that
target, and reports:

- **recall** — how many of the known-planted bugs Beast actually found & recorded
- **found / missed** — which specific ones
- **extras** — recorded findings not in the truth set (a false positive to review,
  or a genuine bonus the truth file didn't know about yet)

Matching is greedy and one-to-one: every (expected, finding) pair is scored by how
many of the expected item's class keywords appear in the finding, and the strongest
pairs are assigned first — so a keyword shared by two bugs (e.g. "hole cards" in
both a poker IDOR and a blackjack leak) goes to the finding that matches *more* of
the expected item, not whichever came first.

## Usage

```bash
python benchmarks/score.py <target> [--truth PATH] [--json]
# default truth path: ~/.beast/benchmarks/<target>.json
```

Typical loop: make a change → run Beast against the lab → `score.py <target>` →
compare recall to the last run.

## Ground-truth files live OUTSIDE the repo

Truth files contain the answer key for a specific lab, so they are **not** committed
here — keep them under `~/.beast/benchmarks/<target>.json` (the default path). That
keeps this tool public without shipping a walkthrough of anyone's training lab.

Shape:

```json
{
  "target": "example.com",
  "expected": [
    {"id": "casino-poker-idor",
     "host": "casino",
     "classes": ["poker", "idor"],
     "desc": "poker hand/{seat_id} IDOR"}
  ]
}
```

- `host` — substring that must appear in the finding's target URL (or text).
- `classes` — any one appearing in the finding's kind/title/note counts; list the
  most *discriminating* keywords (the unique service/bug name) so two similar bugs
  don't collide.
- `desc` / `id` — human labels for the report.
