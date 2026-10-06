# Authentication Security Note

**Project:** Secure Authentication Lab
**Scope:** Local authentication service run on localhost for learning. No real user data.

## 1. Objective
Apply defensive authentication controls and demonstrate each one with automated tests.

## 2. Controls implemented

| Area | Control | Threat addressed | Test that proves it |
|------|---------|------------------|---------------------|
| Password storage | Passwords hashed with salted scrypt (`werkzeug.security`), never stored in plaintext | Database leak exposing passwords; rainbow tables | `test_same_password_gives_different_hashes_salted`, `test_password_is_hashed_not_stored_in_plaintext` |
| Input validation | Server-side checks: username 3-32 chars of `[A-Za-z0-9_]`; password 10-128 chars with upper, lower and digit; non-string input rejected | Injection attempts, malformed input, weak passwords | `test_weak_passwords_rejected`, `test_bad_usernames_rejected`, `test_non_string_input_rejected` |
| Cookies | `HttpOnly`, `Secure`, `SameSite=Strict` | Session theft via XSS, sniffing over http, cross-site request forgery | `test_cookie_has_secure_attributes` |
| Session tokens | 256-bit random token (`secrets.token_urlsafe(32)`), new token every login | Guessing tokens; session fixation | `test_new_session_token_on_each_login` |
| Logout | Session deleted on the server and cookie cleared | Reuse of a stolen or old token | `test_session_grants_access_then_logout_revokes_it`, `test_logged_out_token_cannot_be_reused` |
| Session expiry | 15 minute idle timeout and 8 hour absolute limit | Abandoned or hijacked sessions staying valid | `test_idle_session_expires`, `test_active_session_stays_alive_until_absolute_limit` |
| Rate limiting | 5 failed logins per minute per username and IP, then HTTP 429 with `Retry-After`; correct password is also blocked while locked | Brute force and password guessing | `test_rate_limit_blocks_brute_force`, `test_rate_limit_blocks_even_correct_password_while_locked`, `test_rate_limit_resets_after_window` |
| Generic errors | Same message and status for unknown user and wrong password; a dummy hash check keeps timing similar | Username enumeration | `test_unknown_user_and_wrong_password_give_identical_errors` |
| Response headers | `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`, `Content-Security-Policy` | Clickjacking, content sniffing, caching of sensitive responses | `test_security_headers_present` |

## 3. Test evidence
`python -m unittest -v` runs 20 tests, all passing. See `test_output.txt`.

## 4. Known limitations (honest scope)
- Users, sessions and rate-limit counters are stored **in memory** and are lost on restart. A real system would use a database and Redis.
- No CSRF token. `SameSite=Strict` gives strong protection, but sensitive forms should also use CSRF tokens.
- No multi-factor authentication, email verification or password reset flow.
- No check against lists of breached passwords.
- Rate limiting is per process and per IP and username; it would not work across several servers.
- The service must be served over HTTPS in production. `INSECURE_DEV=1` exists only for localhost testing.

## 5. Recommended next steps
Add a database, MFA, breached-password checks, account lockout alerts, audit logging and a CSRF token.
