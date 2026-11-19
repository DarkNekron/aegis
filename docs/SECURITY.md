# AEGIS — Security

AEGIS handles some of the most sensitive data in an organisation: a map of who can take over the domain. This
document describes how AEGIS protects that data and itself. Report vulnerabilities privately to the repository
owner; do not open public issues for them.

## 1. Scope and threat model

| In scope | Out of scope (by design) |
|---|---|
| A single-analyst or small-team web application bound to `127.0.0.1` by default | Live directory access. AEGIS never connects to, authenticates against, or modifies Active Directory. |
| Hostile uploads (malicious ZIPs, crafted JSON/CSV) | Running collectors or exploitation tooling |
| Browser-based attacks against logged-in users (CSRF, XSS, clickjacking) | Multi-tenant hosting |
| Password guessing, session theft, privilege misuse between roles | Protection against a compromised host OS |

## 2. Authentication
* **Password hashing:** Argon2id via argon2-cffi (t=3, m=64 MiB, p=4, RFC 9106). Hashes are upgraded on login
  when parameters change.
* **Password policy:** 12–128 characters, must not contain the username, and very common or repetitive passwords
  are rejected.
* **No default accounts: first-run setup.** A new installation has no users at all. On its first start AEGIS
  shows a *Create your administrator account* screen. The owner chooses their own username and password there.
  * To stop whoever reaches the page first from claiming the installation, setup needs a one-time **setup code**.
    It has about 79 bits of entropy. It is printed only on the server console (never written to the log) and saved
    to `data/first-run-setup-code.txt`, which only the machine's user can read.
  * Only the SHA-256 of the code is kept in memory, and it is compared in constant time. Attempts share the login
    rate limits and are audited (`first_run_setup`).
  * The code is single-use. Its file is deleted after setup. A restart while setup is pending issues a new code.
  * Once any account exists, `POST /api/auth/setup` is refused with `409` for good. A lock plus a re-check inside
    the transaction stop two parallel requests from both succeeding.
  * The same username and password policy applies, and the account is signed in immediately.
  * Further accounts are created by an administrator (*Settings → Users*), or locally with
    `python -m app.cli create-user <name> --role admin`. The CLI prompts for the password; it is never a
    command-line argument.
* **Uniform failure response:** every failed login, whether the user is unknown, the password is wrong, the account
  is locked or the account is inactive, returns the same `401 Invalid username or password.` For unknown users AEGIS
  still verifies against a dummy hash, so response timing does not reveal which usernames exist.
* **Lockout:** after `AEGIS_LOGIN_MAX_FAILURES` (5) consecutive failures, the account is locked for
  `AEGIS_LOGIN_LOCKOUT_MINUTES` (15).
* **Rate limiting:** token buckets per client IP and per username on `/api/auth/login`
  (`AEGIS_RATE_LIMIT_LOGIN_PER_MIN`, 10), and per user on every authenticated endpoint
  (`AEGIS_RATE_LIMIT_API_PER_MIN`, 300). Responses are `429` with `Retry-After`.

## 3. Sessions
* **Token:** a random 256-bit token (`secrets.token_urlsafe(32)`) in cookie `aegis_session` with `HttpOnly`,
  `SameSite=Strict` and `Path=/`. `Secure` is set when `AEGIS_COOKIE_SECURE=true`, which is required when serving
  over HTTPS.
* **Storage:** sessions are server-side, and only the **SHA-256 of the token** is stored. A leaked database does not
  yield usable session cookies.
* **Expiry:** idle timeout `AEGIS_SESSION_IDLE_MINUTES` (30) and absolute lifetime `AEGIS_SESSION_ABSOLUTE_HOURS` (8).
  Expired rows are deleted.
* **Revocation:** logout revokes the session server-side, so replaying the old cookie fails (tested). Changing a
  password revokes the user's other sessions. An administrator password reset or deactivation revokes all of that
  user's sessions.

## 4. CSRF and cross-origin protection
* Every login issues a per-session CSRF token, stored hashed. Every state-changing request (anything other than
  GET/HEAD/OPTIONS) must send it in `X-CSRF-Token`, and it is compared in constant time. `GET /api/auth/csrf`
  rotates it, for example after a page reload.
* A request carrying an `Origin` header that does not match the `Host` is rejected.
* `SameSite=Strict` cookies add a further independent layer.

## 5. Authorisation (RBAC)

| Capability | Viewer | Security Analyst | Administrator |
|---|:-:|:-:|:-:|
| View dashboards, snapshots, paths, reports, system health | ✅ | ✅ | ✅ |
| Import data, run analyses and simulations, generate reports, validate paths | | ✅ | ✅ |
| Manage users, change risk/analysis settings, view the audit log | | | ✅ |

Roles are enforced by FastAPI dependencies (`require_role`) on every route, and tests cover each role. Safety
rails: administrators cannot demote or deactivate themselves, and the last active administrator can never be removed.

## 6. Audit logging
Logins (success and failure, with the reason recorded server-side only), logouts, password changes and resets, and
user creation and updates are recorded in `audit_log` with user, IP, target and time. Later stages add imports,
analyses, simulations, reports and settings changes. Detail fields are filtered: any key resembling
password/token/secret/csrf/cookie is dropped. Administrators read the log at `GET /api/audit`.

## 7. Input handling and data protection
* **Validation:** every request body and query is validated by Pydantic. Validation errors echo field locations,
  never submitted values.
* **SQL:** the ORM or Core is used with bound parameters only. No SQL is built from strings.
* **Uploads:** see [DATA_FORMATS.md](DATA_FORMATS.md) and the ingestion module. Controls include extension and
  magic-byte agreement, size caps enforced while streaming, random stored names, and ZIP members validated (traversal,
  absolute paths, symlinks, encryption, member count, compression ratio, total size) and read without extraction.
* **Imported text:** treated as untrusted. Control and bidirectional-override characters are stripped and lengths
  capped. Output escaping is the renderer's job (React default, Jinja2 autoescape).
* **Error responses:** generic messages with a request ID. Details go only to the server log, which passes through a
  redaction filter for passwords, tokens, bearer headers and the secret key.
* **Security headers:** strict `Content-Security-Policy` (self only), `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP, and `Cache-Control: no-store` on API responses.

## 8. Deployment guidance
* Keep the default `AEGIS_HOST=127.0.0.1`. If you expose AEGIS on a network, put it behind a TLS-terminating reverse
  proxy, set `AEGIS_COOKIE_SECURE=true` and restrict access to the network. AEGIS deliberately does **not** trust
  `X-Forwarded-For`, so per-IP login limits see the proxy's address. Rely on the per-username limit and lockout.
* Set a strong `AEGIS_SECRET_KEY` (≥ 32 characters). The application refuses to start in `production` without one.
* `AEGIS_ENV=production` disables the interactive API documentation.
* The SQLite database and `data/` contain sensitive directory data. Protect them like a password vault, and never
  commit them (they are git-ignored).

## 9. Known limitations
* The rate limiter is in-process. With several application processes, each enforces its own limits; AEGIS is designed
  to run as one process.
* There is no multi-factor authentication yet.
* Login hashing deliberately costs about 64 MiB and tens of milliseconds per attempt. Combined with the rate limits,
  this bounds memory use on the 16 GB development laptop.
