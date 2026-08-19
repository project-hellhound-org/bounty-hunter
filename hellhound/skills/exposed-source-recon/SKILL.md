---
name: exposed-source-recon
description: Methodology for discovering and exploiting exposed .git directories, subdomain enumeration pivots via OSINT, dangling DNS/CNAME takeovers, and source-code-derived intelligence gathering.
---

# EXPOSED SOURCE & RECON PIVOT METHODOLOGY

Execute early in any engagement, and re-execute whenever a new subdomain, GitHub org, or domain-adjacent lead surfaces mid-engagement.

## 1. Exposed `.git` Directory Discovery
For EVERY discovered host (not just the primary target), test directly rather than relying on directory brute force alone (brute force wordlists frequently miss `.git` due to the leading dot):
```json
{"tool": "curl", "args": {"url": "https://<host>/.git/HEAD", "method": "GET"}}
```
- A response containing `ref: refs/heads/<branch>` confirms an exposed, live git directory — proceed to full dump immediately, this is a near-guaranteed source code + history leak.
- If `/.git/HEAD` 404s, still check `/.git/config` and `/.git/logs/HEAD` independently — some misconfigurations expose only partial paths depending on server rewrite rules.

### Dumping
1. Attempt a direct clone first (fastest path when directory listing is enabled server-side):
```json
{"tool": "shell", "args": {"cmd": "git clone <target>/.git/ recovered-repo"}}
```
2. If direct clone fails (directory listing disabled), fall back to object-graph reconstruction via GitTools or git-dumper, which parses `HEAD`/`packed-refs`/`logs` to enumerate and individually fetch each object:
```json
{"tool": "shell", "args": {"cmd": "gitdumper.sh <target>/.git/ <output_dir>"}}
```
3. Run the extractor to reconstruct the actual working tree from raw objects, then read `README`, config files, and full commit history/diffs for hardcoded secrets, internal hostnames, and comments revealing intended-but-unimplemented security controls.

## 2. Subdomain Pivot via GitHub (Not Just Wayback/Crawlers)
When an OSINT lead (a domain name, company name, or leaked email) yields nothing on Wayback Machine or standard crawling:
1. Search GitHub directly for the domain/company name string — developer repos, even unrelated personal ones, frequently reference internal subdomains, deployment scripts, or backup commands mentioning production hostnames that never appear anywhere else publicly indexed.
2. Specifically check any `README.md`, shell scripts (`*.sh`), CI config (`.github/workflows/*.yml`), and `.env.example` files in matched repos — these routinely contain real internal hostnames, even when actual secrets were properly excluded via `.gitignore`.
3. Any new subdomain pattern discovered this way should be tested against ALL known variations of the target's domains, not just the one it was found under — a subdomain naming convention often repeats across a company's full domain portfolio even if one specific domain is out of scope.

## 3. Dangling CNAME / Subdomain Takeover
For every subdomain enumerated (via recon tooling or the GitHub pivot above):
1. Run automated detection (`subzy` or equivalent) but treat ALL results as unverified leads, not findings — high false-positive rates are the norm, not the exception.
2. Manually verify each flagged host individually:
   - Resolve the CNAME target directly (`dig CNAME <host>`).
   - Check if the CNAME points to a third-party service (cloud CMS, PaaS, static hosting, CDN edge).
   - Request the host directly and inspect BOTH the TLS certificate (does the SAN list include the requested hostname?) AND the response body (does it show a generic "not found"/"not claimed" page specific to that third-party platform, versus the target's OWN generic 404 page reused across unrelated infrastructure)?
   - A certificate SAN mismatch + a platform-specific "claim this domain" response body together confirm a real dangling takeover. Either signal alone is insufficient — some CDN edge nodes return generic 404s with valid wildcard certs and are NOT takeover candidates despite superficially matching a scanner's signature.
3. **Different CNAME targets require different verification** — a dangling record to a CMS platform, an orphaned CDN edge node, and a misconfigured but live API backend are three different situations that a scanner will label identically. Do not treat all "VULNERABLE" scanner output as the same bug class.

## 4. Claiming & Proof (When Takeover Is Confirmed)
1. Register on the third-party platform the CNAME points to (expect friction — signup flows are often built for legitimate customers, not fast PoC claims).
2. Claim the domain via the platform's own domain-verification flow.
3. Host a minimal, clearly-labeled, inert proof page (no forms, no scripts, no data collection) identifying it as security research with a contact handle.
4. Screenshot, log the timestamp, and remove the claim promptly after evidence capture — do not leave a claimed takeover live longer than needed to document it.

## 5. Verification & Evidence
1. For `.git` exposure: cite the specific secret/hostname/logic found in the recovered source, not just "the git folder was exposed."
2. For subdomain takeover: the SAN mismatch + platform-specific response body together are the evidence; capture both.
3. Record:
```json
{"tool": "record_finding", "args": {"title": "Exposed .git Directory Leaking Source Code and Credentials", "kind": "info_disclosure", "severity": "high", "request_ref": "<host>/.git/HEAD", "note": "Full history recovered via <clone/GitTools>. Notable finding: <specific secret or logic>."}}
```
```json
{"tool": "record_finding", "args": {"title": "Subdomain Takeover via Dangling CNAME to <Platform>", "kind": "subdomain_takeover", "severity": "high", "request_ref": "<subdomain>", "note": "CNAME points to unclaimed <platform> resource; confirmed via cert SAN mismatch and platform-specific claim page. Claimed and evidenced via inert PoC page, then released."}}
```

## Rule of Exhaustion
Always re-run Step 1 (`.git` check) against every newly discovered host for the rest of the engagement, not just the initial target — new subdomains surface throughout an assessment, and each one deserves the same check. A scanner marking a host "not vulnerable" for takeover is not authoritative — manually verify anything with an unusual CNAME target regardless of scanner output.
