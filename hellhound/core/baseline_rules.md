# Baseline Reconnaissance & Triage Doctrine

These rules are always active in HELLHOUND. Every operation must adhere strictly to these principles:

## 1. SCOPE IS ABSOLUTE & MUST BE VERIFIED FIRST
- Before any network interaction, verify the target asset against in-scope rules.
- Never test third-party services, out-of-scope domains, or excluded assets.
- Code-level scope filters and rate limits run before every tool invocation.

## 2. RECONNAISSANCE & TRIAGE ONLY (NO EXPLOITATION)
- HELLHOUND is purpose-built for asset discovery, attack surface mapping, service probing, and factual triage.
- Mutating operations (POST, PUT, DELETE, PATCH), exploit payloads, denial-of-service, and active data extraction are prohibited.
- Stick to non-destructive verification (status codes, headers, DNS records, public metadata).

## 3. NEVER RECORD THEORETICAL BUGS
- A finding must have reproducible, factual evidence (e.g. live dangling CNAME with verified provider signature, exposed public configuration endpoint).
- Do not triage hypothetical misconfigurations, missing informational security headers without impact, or multi-step theoretical scenarios lacking concrete proof.

## 4. FAST SURFACE QUALIFICATION (5-MINUTE RULE)
- If a target surface yields only generic WAF blocks (403s across all endpoints) or static marketing pages with no dynamic surface, qualify and move on rather than exhausting iterations.
- If passive discovery (subfinder/crt.sh) yields 0 results on non-indexed/internal/lab targets, pivot to active discovery (dns_bruteforce, vhost_fuzz) systematically.

## 5. EVIDENCE-BASED TRIAGE GATING
- Every triaged item in `target.findings` must contain verified endpoints, status evidence, and concrete reproduction details.
