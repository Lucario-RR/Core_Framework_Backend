# Core Framework Backend

Rust backend for the reusable core user-management platform in this repository.

Stack:

- Rust
- `axum`
- PostgreSQL
- `sqlx`
- JWT access tokens plus refresh cookies
- local signed-upload adapter for private files during development

Reference docs:

- [doc/API_Documentation.openapi.yaml](doc/API_Documentation.openapi.yaml): canonical OpenAPI 3.1 contract
- [doc/API_Documentation.md](doc/API_Documentation.md): human-readable API guide
- [doc/core_user_system_scope.md](doc/core_user_system_scope.md): feature/scope guide
- [doc/Database_Guide.md](doc/Database_Guide.md): PostgreSQL schema guide
- [doc/Error_Handling_Guide.md](doc/Error_Handling_Guide.md): error urgency scale, log location, and troubleshooting steps

## Run Locally

1. Install Rust and Docker.
2. Copy `.env.example` to `.env`.
3. Start PostgreSQL:

```bash
docker compose up -d postgres
```

4. Start the backend:

```bash
cargo run
```

The server listens on `http://127.0.0.1:11451` by default and runs the SQL migrations automatically on startup.

## Maintenance Tool

The repository also includes a separate Cargo binary for local database maintenance. It uses the same `.env` file and the same `DATABASE_URL` as the main backend, but it is compiled only when the `maintenance` feature is enabled.

Create an administrator account:

```powershell
$env:MAINTENANCE_ADMIN_PASSWORD = "replace-with-a-strong-password"
cargo run --features maintenance --bin maintenance -- create-admin --email admin@example.com --display-name "Admin User"
Remove-Item Env:\MAINTENANCE_ADMIN_PASSWORD
```

By default this command:

- connects to the database from `DATABASE_URL`
- runs the same SQL migrations as the main backend
- creates an active account with the `user` and `admin` roles
- verifies the primary email so the account is ready for admin use
- enrols TOTP MFA and prints the authenticator secret, `otpauth://` URI, and one-time recovery codes

You can also pass the password directly, although the environment variable avoids leaving it in shell history:

```bash
cargo run --features maintenance --bin maintenance -- create-admin --email admin@example.com --display-name "Admin User" --password "replace-with-a-strong-password"
```

Useful options:

- `--no-migrations`: connect without running migrations first
- `--leave-email-pending`: create the account without marking the primary email as verified
- `--no-totp`: skip TOTP enrolment. Login will still issue a session; clients can use `user.security.mfaRequired && !user.security.totpEnabled` to show a skippable TOTP enrolment prompt.
- `--require-password-change`: force the account to rotate its password after login

Inspect recent users:

```bash
cargo run --features maintenance --bin maintenance -- list-users --limit 20
```

Build separation:

```bash
# Main backend only
cargo run
cargo build --bin core_framework_backend

# Maintenance tool only
cargo run --features maintenance --bin maintenance -- help
cargo build --features maintenance --bin maintenance
```

The `maintenance` binary is declared with `required-features = ["maintenance"]`, so normal `cargo run` and normal `cargo build` do not compile the maintenance tool.

## Environment

Copy `.env.example` to `.env` before running locally. The backend loads `.env` automatically on startup.

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string used by `sqlx` and automatic migrations. |
| `BIND_ADDR` | IP address and port for the axum HTTP server, for example `127.0.0.1:11451`. |
| `APP_BASE_URL` | Public base URL used when generating external-facing links and signed URLs. |
| `JWT_SECRET` | Secret used to sign JWT access tokens. Replace the example with a long random value. |
| `COOKIE_SECURE` | Marks auth cookies as HTTPS-only when set to `true`; use `false` for plain local HTTP. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to make credentialed API requests. Defaults include `APP_BASE_URL`, `http://localhost:5173`, and `http://127.0.0.1:5173`. |
| `PUBLIC_ADMIN_BOOTSTRAP_ENABLED` | Enables first-admin bootstrap registration when the matching database setting also allows it. |
| `UPLOAD_DIR` | Local directory used by the development file upload/download adapter. |
| `ACCESS_TOKEN_TTL_SECONDS` | Lifetime of bearer access tokens in seconds. |
| `REFRESH_TOKEN_TTL_SECONDS` | Lifetime of refresh token cookies and long-lived sessions in seconds. |
| `PASSWORD_RESET_TTL_SECONDS` | Lifetime of password reset challenges in seconds. |
| `EMAIL_VERIFICATION_TTL_SECONDS` | Lifetime of email verification challenges in seconds. |
| `TOTP_ISSUER` | Label shown in authenticator apps for TOTP MFA setup. |
| `LOG_DIR` | Directory for local debug logs; default example writes `logs/backend-debug.log`. |
| `RUST_LOG` | Rust tracing filter controlling console and file log verbosity. |

## Notes

- File uploads start at `/api/v1/files/uploads`, then use the returned signed local upload URL under `/internal/uploads/...`.
- Private downloads start at `/api/v1/me/files/{fileId}/download`, which returns a short-lived signed local download URL.
- Bootstrap admin registration is controlled by both `PUBLIC_ADMIN_BOOTSTRAP_ENABLED` and the seeded system setting `registration.bootstrap_admin_enabled`.
- New accounts require a unique username stored in `iam.account.public_handle`; login accepts that username, email, or a login-enabled phone number through the preferred `login` field, with `username`, `email`, `phoneNumber`, and `phone` accepted as explicit aliases. Username self-service changes are rate-limited by `account.username.change_cooldown_seconds`.
- Invitation registration is stored in `auth.registration_invite`; only invite code hashes are persisted, while generated or admin-provided codes are returned once from the admin API. Admins can list invite metadata and revoke unused invites.
- Admin-created custom roles are stored in `iam.role`; per-user role expiry is stored on `iam.account_role.expires_at` and expired roles are ignored when issuing access-token roles/scopes. Deleting a non-protected role soft-deletes it and expires active assignments; `admin` and `user` cannot be deleted.
- User settings already have backend coverage through `/api/v1/me`, `/api/v1/me/avatar`, `/api/v1/me/emails`, and `/api/v1/me/phones`; phone changes intentionally go through add, verify, and make-primary steps.
- Frontends can read `GET /api/v1/auth/password/policy` for password prechecks; admins can update the same backend-enforced policy through `PATCH /api/v1/admin/password-policy`.
- Browser clients must send credentialed auth requests, for example `fetch(url, { credentials: "include" })`. Calls to `/api/v1/auth/refresh` must also send `X-CSRF-Token` with the current `csrf_token` cookie value.
- Local debug logs are written to `logs/backend-debug.log` by default. Set `LOG_DIR` to move them somewhere else.
