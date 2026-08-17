---
name: auth-bypass
description: Targeted methodology for authentication bypass and password reset flaws, including host header injection, email leak via HTML scraping, and REST token manipulation.
---

# AUTHENTICATION BYPASS METHODOLOGY

When dealing with a password reset or "forgot password" auth flow, follow these exact steps to uncover logic flaws.

## 1. Tool Selection & Execution Strategy
**CRITICAL RULE:** For a directed authentication bypass or specific web endpoint task, **DO NOT waste time on infrastructure recon.**
- **DO NOT USE:** `subfinder`, `dnsx`, `naabu`, `nmap`, or any port scanning / DNS brute-forcing tools. These are completely irrelevant to a single-endpoint web application task and waste time.
- **DO USE:** 
  - `curl` for manual HTTP requests and checking headers/bodies.
  - `spider` or `katana` for discovering endpoints, content discovery, and finding leaked information (like emails in HTML).
  - Web interaction tools to scrape HTML, extract sensitive data, and send `POST` requests to authentication endpoints.
  
Keep it straightforward: Do the directed task using only the necessary web-layer tools.

## 2. Map the Complete Flow
- Identify the exact API endpoints used for the authentication flow, such as:
  - `/api/auth/forgot` or similar (POST)
  - `/api/auth/login` (POST)
  - `/api/auth/reset` or similar (POST/GET)
- Enumerate valid users. If the app returns a generic success message on forgot password but you don't know the target email, you MUST find the email.

## 3. Deep Content Scraping & API Inspection for Leaks
- Do not just rely on HTML responses or frontend scraping. Modern SPAs load their data from backend APIs.
- **CRITICAL:** If the spider discovers ANY raw data API endpoints (e.g., endpoints returning JSON, content feeds, user lists, or configuration), you MUST fetch those exact endpoints using `curl`. Do not assume the endpoint names; inspect the spider's output for anything that looks like an API route.
- JSON responses from REST APIs often contain unfiltered backend data, including author emails, IDs, and hidden fields that are completely invisible in the frontend HTML.
- Always extract all email addresses from BOTH the HTML source and the raw JSON API responses. Authors or staff often leak their corporate email in the author bio or metadata.

## 4. The Reset Link Attack (Host Header Injection)
If the application uses a REST API to send a password reset link to the user:
- How does the server know what domain to put in the reset link? It often uses the `Host` header from your HTTP request.
- **The Attack:** Intercept the forgot password request. Change the `Host` header to your own controlled server (e.g., `Host: attacker.com` or a webhook).
- When the server generates the email to the target, the reset link will point to `http://attacker.com/reset?token=XYZ`. 
- You receive the token on your server and can then use it on the real application to change the target's password.

## 5. The Direct-to-Server Reset Link Attack
Sometimes the backend is misconfigured to send the reset link *to the server's own logs* or to *the client response*, or the application blindly trusts the reset link generation.
- Initiating the forgot password flow for the leaked email might generate a backend reset link that is accessible or logged.
- **VULNERABILITY CHECK:** If the reset link is sent to the web server's own endpoint instead of an external email, you might be able to capture it if there's a misconfigured logging endpoint, or if you can manipulate the host header to point back to an endpoint you control or can view.
