# Rule-based agent → AI-brain upgrade program

The module-agents in `hellhound/modules/` were built for the *old* architecture:
standalone **rule-based** pentest scanners that sweep every URL with fixed logic
and emit raw results. Now they run under an AI-brain orchestrator (XBOW/Horizon
style). Each should stop being a blind sweeper and instead (a) use the **already-
discovered surface** to focus on the endpoints/params where its class can
actually live, and (b) return **actionable, reasoned intelligence** the brain can
act on — not just "a thing exists."

The template (first applied to CORS): a `_*_from_surface` scorer that ranks
discovered endpoints/params for the class, the executor merges those targets into
what the module sweeps (so the real one is never missed), and it returns the
prioritised targets **with a reason each** + a `*_note` telling the brain what to
do next.

## Status

| Agent | Was (rule-based) | Intelligence upgrade | Status |
|-------|------------------|----------------------|--------|
| `corsbuster` / `cors_checker` | sweeps every URL for ACAO/ACAC | `_data_endpoints_from_surface` scores endpoints (JSON/data + credentialed = top; login/static/favicon = 0); prioritises the data endpoints where a credentialed CORS read bites; returns `smart_cors_targets` + reasons | ✅ done (12 tests) |
| `wafbuster` | detects "a WAF exists" | reuses `stealth.waf_evasion_profile` to return the WAF-family-specific **tactics + coherent header set** + a note to apply `stealth`/`waf_evasion_probe` | ✅ done |
| `fuzz_hunter` | fuzzes params with a generic wordlist | consume `map_surface`/param-type inference → send **type-appropriate payloads per param** (numeric_id→IDOR ids, file_path→traversal, url→SSRF, search→SQLi/XSS); prioritise high-value params | ▢ next |
| `surface_auditor` | audits ports/headers/surface | rank findings by exploitability; emit a **class→endpoint attack plan** the brain can execute, not a flat dump | ▢ |
| `graphql` | probes GraphQL | if introspection is open, auto-surface the **sensitive queries/mutations + injectable args**, not just the schema | ▢ |
| `js_miner` | finds endpoints in JS | ✅ already extended with `js_intel` (bundled secrets/PII, not just endpoints) | ✅ (earlier) |
| `sourceauditor` / `blobunpacker` | unpack sourcemaps | prioritise **secrets/auth-logic/endpoints** over raw dumps; feed the secrets store | ▢ |
| `cloudscout` | cloud recon | map discovered buckets/metadata to **testable SSRF/takeover targets** | ▢ |
| `transport_auditor` | TLS/transport audit | surface only **exploitable** transport issues (downgrade, mixed-content auth), suppress informational noise | ▢ |
| `hydra` | brute force | pull the **real usernames** harvested on this target + the confirmed login endpoint, instead of generic lists | ▢ |

## Principle
Every upgrade must be **additive and safe**: it never removes the module's
coverage (targets are *merged in*, never *replaced*), it's wrapped so a failure
in the intelligence layer can't break the underlying scan, and it returns its
reasoning so the brain (and a human reading the result) can see *why* a target
was chosen. Unit-test the scorer/selector against a synthetic surface.
