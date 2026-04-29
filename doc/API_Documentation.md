# Core User Management API Documentation

The canonical API contract is [API_Documentation.openapi.yaml](API_Documentation.openapi.yaml).

Implementation note:

- the Rust backend in this repository also exposes signed local transport helpers under `/internal/uploads/*` and `/internal/files/*`
- those internal routes make the documented file-intent flow runnable in local development without requiring an external object store
- they are implementation details, not part of the stable public API contract

Error note:

- API error payloads include `error.urgencyLevel` on a 1-9 scale so clients and operators can distinguish low-friction request fixes from higher-urgency backend failures
- see [Error_Handling_Guide.md](Error_Handling_Guide.md) for the urgency scale, local log path, and common recovery steps

Health check:

- the backend exposes an unauthenticated `GET /api/v1/health` endpoint inside the versioned public API
- a healthy server returns the standard acknowledgement envelope with `data.status` set to `ok` and `data.message` set to `service healthy`
- use it for load balancers, uptime monitors, deployment smoke tests, and simple frontend/backend connectivity checks

MFA login behavior:

- `/auth/login` returns `202` with an MFA challenge only when the account already has an active confirmed TOTP factor
- MFA enrollment policy is reported on successful session responses as `data.user.security.mfaRequired`; clients should treat `mfaRequired && !totpEnabled` as a skippable TOTP enrollment prompt, not as a failed login state
- global and role MFA policy is captured for newly created accounts as an account-level enrollment flag; existing users are not blocked at login merely because they have no TOTP factor

Login, invitation, and password-policy behavior:

- `/auth/login` accepts a preferred `login` field that can contain username, email address, or login-enabled phone number; explicit `username`, `email`, `phoneNumber`, and `phone` alias fields are also accepted
- `/auth/register` requires a unique `username` and accepts optional `invitationCode`; when `registration.invite_only` is true, a valid invitation code is required and its role list is applied to the new account
- `PATCH /me` can update the username; self-service username changes are rate-limited by `account.username.change_cooldown_seconds`
- `GET /auth/password/policy` returns the active password rules for frontend precheck; the backend enforces the same policy on registration, admin-created accounts, password change, and password reset
- admins can list, create, and revoke invitation codes through `/admin/invitations`; creation supports single-use, multi-use, generated codes, admin-provided codes, and no-expiry codes
- admins can create, edit, and delete custom roles through `/admin/roles`, read assignable permissions through `/admin/permissions`, and set per-user role expiry with `roleAssignments[].expiresAt`; deleting a role expires active assignments, while `admin` and `user` are protected
- admins can create accounts as `active` or `pending`; pending accounts are treated as waiting for activation and cannot log in until activated
- user settings are already covered by `/me`, `/me/avatar`, `/me/emails`, and `/me/phones`; phone changes remain verification-based through the phone create, verify, and make-primary flow
- admins can manage the password policy through `/admin/password-policy`
- `POST /admin/users` now returns a one-time `initialPassword` and copy-ready `accountText` so the frontend can offer download/copy actions after account creation

This companion note explains what changed:

- the original promoted OpenAPI file had copied the full PriceTracker reference surface
- the canonical spec is now trimmed to the reusable core user-management layer only
- all business-domain APIs were removed from the canonical spec

Removed from the canonical API contract:

- catalog
- shops
- prices
- purchases
- comparisons
- watchlists
- alerts
- price moderation
- generic admin table CRUD

Retained in the canonical API contract:

- auth and session flows
- invitation registration and multi-key login
- profile and avatar management
- self-service account deactivation
- account-owned private file handling for core use cases
- password reset and MFA
- passkeys
- verified email and phone management, including verification resend and primary email change flow start
- active session listing and session revocation
- security event history and suspicious-login reporting
- legal document and consent endpoints
- privacy request workflows for export, erasure, rectification, and account deletion
- cookie preference endpoints
- admin user management
- admin settings and overview
- admin invitation, role, user-settings, security event, audit log, and per-user session/security inspection

If this Markdown guide and the OpenAPI file ever disagree, treat [API_Documentation.openapi.yaml](API_Documentation.openapi.yaml) as the source of truth.
