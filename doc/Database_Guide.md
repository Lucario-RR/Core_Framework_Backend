# Core User System SQL Database Guide

This guide turns the feature scope in `doc/core_user_system_scope.md` into a reusable SQL database design for a robust user, auth, admin, and security core.

It is intentionally focused on the reusable platform layer:

- account lifecycle
- identity and contact management
- password and credential management
- sessions and device control
- MFA / 2FA / recovery
- admin control and policy settings
- audit, security monitoring, and notifications
- privacy, retention, and deletion workflows

The examples below are PostgreSQL-friendly SQL, but the model is portable to other relational databases by swapping types such as `JSONB`, `INET`, and `BYTEA`.

Implementation note:

- the concrete Rust backend in this repository keeps the same schema split and table boundaries, but it makes a few API-driven additions and naming simplifications
- examples include `privacy.legal_document` for the published legal-document endpoint, `auth.phone_verification_challenge` for phone verification, explicit passkey ceremony tables, and `ops.setting_definition.key` instead of a longer `setting_key` column name
- where this guide and the checked-in migration differ, treat the migration as the executable source of truth and use this guide as the design rationale

## 1. Design goals

The schema should be:

- robust under failure, retries, and admin operations
- reusable across multiple Rust backend projects
- normalized enough to avoid duplicated facts
- secure by default for passwords, tokens, secrets, and logs
- explicit about account state, verification, restrictions, and history
- ready for both the mandatory scope and the optional extensions

## 2. Robust design rules

These rules shape the structure more than any one table.

1. Keep current state and history separately.
   Store the current account state on the main row, but keep status transitions, restrictions, audit events, and security events in append-only history tables.

2. Do not overload one enum with unrelated states.
   Use `account.status_code` for lifecycle state, and keep email verification, password rotation, and temporary restrictions in their own tables/columns.

3. Normalize repeating facts.
   Multiple emails, phones, sessions, MFA methods, recovery codes, and notifications should all be child tables, not repeated columns.

4. Hash anything that can be replayed.
   Store password hashes, session token hashes, refresh token hashes, reset token hashes, and recovery code hashes. Never store raw reusable secrets in plaintext.

5. Encrypt anything the server must read back.
   TOTP secrets and similar shared secrets should be encrypted at rest, not hashed.

6. Make security-relevant writes idempotent.
   Critical writes such as registration, password reset, email change, session revoke-all, and admin freeze should support idempotency keys.

7. Prefer time-based validity over booleans alone.
   `starts_at`, `ends_at`, `expires_at`, `consumed_at`, and `revoked_at` are more reliable than only `is_active`.

8. Keep operational throttling out of the hot SQL path where possible.
   Use cache or Redis for live rate-limit counters, but persist lockout decisions, challenges, and security events in SQL.

9. Separate audit logs from security events.
   Audit logs answer "who changed what"; security events answer "what risky thing happened".

10. Build for deletion and retention from day one.
    Use soft deletion where needed, define retention policies, and support legal hold and privacy workflows explicitly.

## 3. Logical schema split

Recommended SQL schema namespaces:

| Schema | Purpose |
|---|---|
| `iam` | accounts, contacts, roles, permissions, status, restrictions |
| `auth` | passwords, sessions, MFA, passkeys, challenges, login hardening |
| `ops` | settings, audit, security events, idempotency, notifications, admin workflow |
| `privacy` | retention, consent, deletion/export requests, legal hold |
| `file` | shared file storage metadata for avatars and export packages |

If the project prefers a single schema, keep the same table boundaries and just prefix names consistently.

## 4. Table inventory by priority

### 4.1 Must-have tables

- `iam.account`
- `iam.account_profile`
- `iam.account_email`
- `iam.account_phone`
- `iam.account_status_history`
- `iam.account_restriction`
- `auth.authenticator`
- `auth.password_credential`
- `auth.password_history`
- `auth.email_verification_challenge`
- `auth.phone_verification_challenge`
- `auth.password_reset_challenge`
- `auth.session`
- `auth.totp_factor`
- `auth.recovery_code_set`
- `auth.recovery_code`
- `auth.passkey_registration_challenge`
- `auth.passkey_authentication_challenge`
- `iam.role`
- `iam.permission`
- `iam.role_permission`
- `iam.account_role`
- `ops.setting_definition`
- `ops.system_setting`
- `ops.audit_log`
- `ops.security_event`
- `ops.idempotency_key`
- `ops.notification`
- `ops.notification_delivery`
- `privacy.legal_document`
- `privacy.consent_record`
- `privacy.privacy_notice_version`
- `privacy.cookie_consent`
- `privacy.retention_policy`
- `privacy.data_subject_request`
- `privacy.legal_hold`
- `file.storage_object`
- `file.file_asset`

### 4.2 Important tables

- `auth.account_email_change_request`
- `auth.login_challenge`
- `auth.account_lockout`
- `ops.account_setting`
- `ops.email_domain_rule`
- `ops.security_report`
- `ops.notification_preference`
- `file.file_attachment`

### 4.3 Optional extension tables

- `auth.registration_draft`
- `auth.registration_invite`
- `auth.registration_approval`
- `auth.external_identity`
- `auth.passkey_credential`
- `auth.trusted_device`
- `auth.sms_factor`
- `ops.admin_action_approval`
- `ops.admin_case`
- `ops.admin_case_note`
- `ops.admin_impersonation_session`
- `privacy.cookie_definition`
- `ops.outbox_event`

Alignment note:

- because the current API contract exposes phone verification, legal document discovery, cookie preferences, passkey ceremonies, and account-owned private file flows, the implementation-grade schema should promote the related tables out of the optional bucket
- `auth.phone_verification_challenge`, `privacy.legal_document`, `privacy.consent_record`, `privacy.privacy_notice_version`, `privacy.cookie_consent`, `file.storage_object`, and `file.file_asset` are now part of the practical baseline
- passkey ceremonies also benefit from explicit registration/authentication challenge rows when the backend wants durable replay protection and a runnable local implementation

## 5. Core table structure

## 5.1 `iam` schema

### `iam.account`

Top-level account identity.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| public_handle | VARCHAR(80) | No |  | normalized unique username; accepted as a login identifier |
| username_changed_at | TIMESTAMPTZ | Yes |  | last explicit username change, used by the username cooldown policy |
| status_code | VARCHAR(30) | No |  | stored lifecycle state such as `pending`, `awaiting_setup`, `active`, `deleted` |
| created_by_account_id | UUID | Yes | FK -> iam.account.id | null for self-registration |
| activated_at | TIMESTAMPTZ | Yes |  | |
| last_login_at | TIMESTAMPTZ | Yes |  | |
| deleted_at | TIMESTAMPTZ | Yes |  | soft delete marker |
| created_at | TIMESTAMPTZ | No |  | |
| updated_at | TIMESTAMPTZ | No |  | |

Recommended constraints:

- unique case-insensitive `public_handle`
- check allowed `status_code` values

Design note:

- Keep this row lean.
- Do not store password hashes, phone numbers, TOTP secrets, or session tokens here.

### `iam.account_profile`

Non-auth profile and preference fields.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| account_id | UUID | No | PK/FK -> iam.account.id | one-to-one |
| display_name | VARCHAR(160) | Yes |  | optional |
| locale | VARCHAR(20) | Yes |  | |
| timezone_name | VARCHAR(80) | Yes |  | |
| region_code | VARCHAR(10) | Yes |  | optional |
| avatar_file_id | UUID | Yes | FK -> file.file_asset.id | optional shared file module |
| created_at | TIMESTAMPTZ | No |  | |
| updated_at | TIMESTAMPTZ | No |  | |

### `iam.account_status_history`

Append-only status transition history.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| from_status_code | VARCHAR(30) | Yes |  | null for first state |
| to_status_code | VARCHAR(30) | No |  | |
| reason_code | VARCHAR(50) | Yes |  | `REGISTERED`, `ADMIN_RESTORE`, `SOFT_DELETE` |
| reason_text | TEXT | Yes |  | admin/self-service reason |
| changed_by_account_id | UUID | Yes | FK -> iam.account.id | null for system change |
| request_id | UUID | Yes |  | correlation |
| changed_at | TIMESTAMPTZ | No |  | |

### `iam.account_restriction`

Tracks temporary or durable account restrictions separately from the base lifecycle state.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| restriction_type | VARCHAR(30) | No |  | `freeze`, `suspend`, `login_disabled` |
| status_code | VARCHAR(20) | No |  | `active`, `lifted`, `expired` |
| reason_code | VARCHAR(50) | Yes |  | |
| reason_text | TEXT | Yes |  | required for admin actions |
| starts_at | TIMESTAMPTZ | No |  | |
| ends_at | TIMESTAMPTZ | Yes |  | null for indefinite |
| created_by_account_id | UUID | No | FK -> iam.account.id | |
| lifted_by_account_id | UUID | Yes | FK -> iam.account.id | |
| lifted_at | TIMESTAMPTZ | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

Recommended index:

- `(account_id, restriction_type, status_code, ends_at)`

### `iam.account_email`

Supports primary, secondary, backup, and recovery email addresses.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| email | VARCHAR(320) | No |  | original case-preserved form |
| normalized_email | VARCHAR(320) | No |  | lowercase/canonical lookup value |
| email_role | VARCHAR(30) | No |  | `PRIMARY`, `SECONDARY`, `BACKUP`, `RECOVERY` |
| is_login_enabled | BOOLEAN | No |  | |
| is_primary_for_account | BOOLEAN | No |  | |
| verification_status | VARCHAR(20) | No |  | `pending`, `verified`, `revoked` |
| verified_at | TIMESTAMPTZ | Yes |  | |
| reverification_required_at | TIMESTAMPTZ | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |
| updated_at | TIMESTAMPTZ | No |  | |
| deleted_at | TIMESTAMPTZ | Yes |  | soft delete |

Recommended constraints:

- unique active email per account: `(account_id, normalized_email)` where `deleted_at` is null
- one active primary email per account
- optionally one globally unique active login email if the product forbids email sharing across accounts

### `iam.account_phone`

Optional multi-phone support for recovery and fallback flows.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| e164_phone_number | VARCHAR(20) | No |  | normalized E.164 |
| phone_role | VARCHAR(30) | No |  | `PRIMARY`, `SECONDARY`, `BACKUP`, `RECOVERY` |
| is_login_enabled | BOOLEAN | No |  | allows phone number to be used as a login identifier |
| is_sms_enabled | BOOLEAN | No |  | |
| is_primary_for_account | BOOLEAN | No |  | |
| verification_status | VARCHAR(20) | No |  | `pending`, `verified`, `revoked` |
| verified_at | TIMESTAMPTZ | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |
| updated_at | TIMESTAMPTZ | No |  | |
| deleted_at | TIMESTAMPTZ | Yes |  | |

### `iam.role`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| code | VARCHAR(40) | No |  | `USER`, `ADMIN`, `SUPPORT` |
| name | VARCHAR(80) | No |  | |
| is_system_role | BOOLEAN | No |  | |
| requires_mfa | BOOLEAN | No |  | supports role-level MFA policy |
| created_at | TIMESTAMPTZ | No |  | |
| updated_at | TIMESTAMPTZ | No |  | changes when an admin edits a role |
| deleted_at | TIMESTAMPTZ | Yes |  | soft delete marker; deleted roles no longer grant roles/scopes |

### `iam.permission`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| code | VARCHAR(80) | No |  | |
| name | VARCHAR(120) | No |  | |
| description | TEXT | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `iam.role_permission`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| role_id | UUID | No | PK/FK -> iam.role.id | |
| permission_id | UUID | No | PK/FK -> iam.permission.id | |
| granted_at | TIMESTAMPTZ | No |  | |

### `iam.account_role`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| account_id | UUID | No | PK/FK -> iam.account.id | |
| role_id | UUID | No | PK/FK -> iam.role.id | |
| granted_by_account_id | UUID | Yes | FK -> iam.account.id | |
| granted_at | TIMESTAMPTZ | No |  | |
| expires_at | TIMESTAMPTZ | Yes |  | null for indefinite role assignment; expired rows no longer contribute roles/scopes |

## 5.2 `auth` schema

### `auth.authenticator`

Common parent row for password, TOTP, passkey, and SMS factors.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| authenticator_type | VARCHAR(30) | No |  | `PASSWORD`, `TOTP`, `PASSKEY`, `SMS_OTP` |
| usage_type | VARCHAR(30) | No |  | `PRIMARY`, `MFA` |
| display_label | VARCHAR(120) | Yes |  | |
| status | VARCHAR(20) | No |  | `pending`, `active`, `revoked`, `lost` |
| enrolled_at | TIMESTAMPTZ | No |  | |
| confirmed_at | TIMESTAMPTZ | Yes |  | |
| last_used_at | TIMESTAMPTZ | Yes |  | |
| revoked_at | TIMESTAMPTZ | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

Recommended constraint:

- partial unique index enforcing only one active password authenticator per account

### `auth.password_credential`

Current password verifier.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| authenticator_id | UUID | No | PK/FK -> auth.authenticator.id | must be `PASSWORD` |
| password_hash | TEXT | No |  | |
| salt_value | BYTEA | No |  | explicit per-password salt |
| hash_algorithm | VARCHAR(40) | No |  | `ARGON2ID` |
| hash_parameters_json | JSONB | No |  | memory, iterations, lanes, version |
| password_version | INTEGER | No |  | increments on change |
| changed_at | TIMESTAMPTZ | No |  | |
| must_rotate | BOOLEAN | No |  | forced reset on next login |
| compromised_at | TIMESTAMPTZ | Yes |  | |

### `auth.password_history`

Historical password verifiers for reuse prevention.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| password_hash | TEXT | No |  | |
| salt_value | BYTEA | No |  | |
| hash_algorithm | VARCHAR(40) | No |  | |
| hash_parameters_json | JSONB | No |  | |
| password_version | INTEGER | No |  | retired version |
| valid_from | TIMESTAMPTZ | No |  | |
| valid_to | TIMESTAMPTZ | No |  | |
| stored_at | TIMESTAMPTZ | No |  | |

### `auth.external_identity`

Optional external provider account link.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| provider_code | VARCHAR(40) | No |  | `google`, `apple`, `oidc`, `saml` |
| provider_subject | VARCHAR(320) | No |  | provider-side subject |
| provider_email | VARCHAR(320) | Yes |  | |
| linked_at | TIMESTAMPTZ | No |  | |
| last_login_at | TIMESTAMPTZ | Yes |  | |
| is_active | BOOLEAN | No |  | |

Recommended constraint:

- unique `(provider_code, provider_subject)`

### `auth.passkey_credential`

Optional WebAuthn/FIDO passkey support.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| authenticator_id | UUID | No | PK/FK -> auth.authenticator.id | must be `PASSKEY` |
| rp_id | VARCHAR(255) | No |  | relying party ID |
| webauthn_user_handle | BYTEA | No |  | |
| credential_id | BYTEA | No |  | |
| public_key_cose | BYTEA | No |  | |
| aaguid | UUID | Yes |  | |
| sign_count | BIGINT | Yes |  | |
| transports_json | JSONB | Yes |  | |
| user_verification_policy | VARCHAR(30) | Yes |  | |

Recommended constraint:

- unique `(rp_id, credential_id)`

### `auth.totp_factor`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| authenticator_id | UUID | No | PK/FK -> auth.authenticator.id | must be `TOTP` |
| secret_ciphertext | BYTEA | No |  | encrypted at rest |
| key_reference | VARCHAR(120) | Yes |  | KMS/HSM ref |
| otp_algorithm | VARCHAR(20) | No |  | `SHA1`, `SHA256`, `SHA512` |
| digits | SMALLINT | No |  | usually 6 or 8 |
| period_seconds | SMALLINT | No |  | usually 30 |
| issuer_label | VARCHAR(120) | Yes |  | |
| confirmed_at | TIMESTAMPTZ | Yes |  | |

### `auth.sms_factor`

Optional SMS fallback if the project truly needs it.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| authenticator_id | UUID | No | PK/FK -> auth.authenticator.id | must be `SMS_OTP` |
| account_phone_id | UUID | No | FK -> iam.account_phone.id | verified phone only |
| confirmed_at | TIMESTAMPTZ | Yes |  | |
| revoked_at | TIMESTAMPTZ | Yes |  | |

### `auth.recovery_code_set`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| code_count | SMALLINT | No |  | |
| status | VARCHAR(20) | No |  | `active`, `replaced`, `revoked`, `exhausted` |
| issued_at | TIMESTAMPTZ | No |  | |
| replaced_by_set_id | UUID | Yes | FK -> auth.recovery_code_set.id | |
| revoked_at | TIMESTAMPTZ | Yes |  | |

### `auth.recovery_code`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| recovery_code_set_id | UUID | No | FK -> auth.recovery_code_set.id | |
| sequence_number | SMALLINT | No |  | display order only |
| code_hash | TEXT | No |  | hashed, not raw |
| salt_value | BYTEA | No |  | |
| hash_algorithm | VARCHAR(40) | No |  | |
| used_at | TIMESTAMPTZ | Yes |  | one-time use |
| created_at | TIMESTAMPTZ | No |  | |

### `auth.email_verification_challenge`

Supports registration verification, resend, email change confirmation, and forced re-verification.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_email_id | UUID | No | FK -> iam.account_email.id | |
| purpose_code | VARCHAR(40) | No |  | `REGISTER`, `CHANGE_OLD`, `CHANGE_NEW`, `REVERIFY` |
| challenge_hash | TEXT | No |  | hash of token or OTP |
| delivery_channel | VARCHAR(20) | No |  | `email_link`, `email_otp` |
| expires_at | TIMESTAMPTZ | No |  | |
| consumed_at | TIMESTAMPTZ | Yes |  | |
| invalidated_at | TIMESTAMPTZ | Yes |  | |
| request_ip | INET | Yes |  | |
| request_user_agent | TEXT | Yes |  | |
| attempt_count | INTEGER | No |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `auth.account_email_change_request`

Tracks email change approval across old and new addresses.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| old_account_email_id | UUID | No | FK -> iam.account_email.id | |
| new_email | VARCHAR(320) | No |  | |
| new_normalized_email | VARCHAR(320) | No |  | |
| status | VARCHAR(20) | No |  | `pending`, `approved`, `cancelled`, `expired`, `completed` |
| old_address_confirmed_at | TIMESTAMPTZ | Yes |  | |
| new_address_confirmed_at | TIMESTAMPTZ | Yes |  | |
| expires_at | TIMESTAMPTZ | No |  | |
| completed_at | TIMESTAMPTZ | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `auth.password_reset_challenge`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| requested_email_id | UUID | Yes | FK -> iam.account_email.id | |
| password_version_at_issue | INTEGER | No |  | reject stale reset flows |
| challenge_hash | TEXT | No |  | hash of token or OTP |
| expires_at | TIMESTAMPTZ | No |  | |
| consumed_at | TIMESTAMPTZ | Yes |  | |
| invalidated_at | TIMESTAMPTZ | Yes |  | |
| request_ip | INET | Yes |  | |
| request_user_agent | TEXT | Yes |  | |
| attempt_count | INTEGER | No |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `auth.session`

Current and historical authenticated sessions.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| session_token_hash | TEXT | Yes |  | if session cookie identifier is used |
| refresh_token_hash | TEXT | Yes |  | if refresh tokens are used |
| authenticated_aal | SMALLINT | No |  | 1, 2, or 3 style level |
| remember_me | BOOLEAN | No |  | |
| user_agent | TEXT | Yes |  | |
| ip_address | INET | Yes |  | |
| device_label | VARCHAR(120) | Yes |  | user-facing device name |
| device_fingerprint_hash | CHAR(64) | Yes |  | optional privacy-conscious hash |
| created_at | TIMESTAMPTZ | No |  | |
| last_seen_at | TIMESTAMPTZ | Yes |  | |
| idle_expires_at | TIMESTAMPTZ | No |  | |
| absolute_expires_at | TIMESTAMPTZ | No |  | |
| revoked_at | TIMESTAMPTZ | Yes |  | |
| revoke_reason_code | VARCHAR(40) | Yes |  | |

### `auth.trusted_device`

Optional trusted device model for step-up reduction.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| device_fingerprint_hash | CHAR(64) | No |  | |
| device_label | VARCHAR(120) | Yes |  | |
| first_seen_at | TIMESTAMPTZ | No |  | |
| last_seen_at | TIMESTAMPTZ | Yes |  | |
| trust_expires_at | TIMESTAMPTZ | Yes |  | |
| revoked_at | TIMESTAMPTZ | Yes |  | |

### `auth.login_challenge`

Challenge rows for MFA, suspicious login approval, or sensitive action step-up.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| session_id | UUID | Yes | FK -> auth.session.id | may be null before session is created |
| challenge_type | VARCHAR(40) | No |  | `MFA_REQUIRED`, `STEP_UP`, `NEW_DEVICE_APPROVAL`, `CAPTCHA` |
| delivery_channel | VARCHAR(20) | Yes |  | `totp`, `email_link`, `push`, `sms` |
| target_hash | CHAR(64) | Yes |  | destination hash if needed |
| risk_score | NUMERIC(5,2) | Yes |  | |
| status | VARCHAR(20) | No |  | `pending`, `satisfied`, `expired`, `cancelled` |
| expires_at | TIMESTAMPTZ | No |  | |
| satisfied_at | TIMESTAMPTZ | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `auth.account_lockout`

Persisted lockout/backoff decisions. Live counters can still be maintained in Redis.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | Yes | FK -> iam.account.id | |
| subject_type | VARCHAR(20) | No |  | `ACCOUNT`, `EMAIL`, `IP` |
| subject_key_hash | CHAR(64) | No |  | normalized email or IP hashed if needed |
| reason_code | VARCHAR(40) | No |  | `FAILED_LOGIN_THRESHOLD`, `RESET_ABUSE` |
| failure_count | INTEGER | No |  | |
| locked_until | TIMESTAMPTZ | No |  | |
| created_at | TIMESTAMPTZ | No |  | |
| lifted_at | TIMESTAMPTZ | Yes |  | |

### `auth.registration_draft`

Optional anonymous or partial pre-registration draft.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| draft_token_hash | TEXT | No |  | |
| email_hint | VARCHAR(320) | Yes |  | |
| payload_json | JSONB | Yes |  | |
| expires_at | TIMESTAMPTZ | No |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `auth.registration_invite`

Optional invite-only registration control.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| invite_code_hash | TEXT | No |  | |
| email | VARCHAR(320) | Yes |  | optional original invitee email |
| normalized_email | VARCHAR(320) | Yes |  | optional email binding for code use |
| role_codes_json | JSONB | No |  | roles granted when the code is consumed |
| created_by_account_id | UUID | Yes | FK -> iam.account.id | |
| status | VARCHAR(20) | No |  | `active`, `consumed`, `expired`, `revoked` |
| expires_at | TIMESTAMPTZ | Yes |  | null means no expiry |
| max_uses | INTEGER | No |  | supports single-use and multi-use codes |
| use_count | INTEGER | No |  | incremented transactionally during account creation |
| consumed_at | TIMESTAMPTZ | Yes |  | set when `use_count` reaches `max_uses` |
| last_used_at | TIMESTAMPTZ | Yes |  | |
| revoked_at | TIMESTAMPTZ | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

Design note:

- Store only `invite_code_hash`, even when an admin provides a custom code string. The plaintext code is returned only in the create response.

### `auth.registration_approval`

Optional staged approval before activation.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| approval_status | VARCHAR(20) | No |  | `pending`, `approved`, `rejected` |
| requested_at | TIMESTAMPTZ | No |  | |
| decided_by_account_id | UUID | Yes | FK -> iam.account.id | |
| decided_at | TIMESTAMPTZ | Yes |  | |
| reason_text | TEXT | Yes |  | |

## 5.3 `ops` schema

### `ops.setting_definition`

Defines which settings exist and their expected type.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| setting_key | VARCHAR(120) | No |  | |
| scope_type | VARCHAR(20) | No |  | `SYSTEM`, `ACCOUNT` |
| value_type | VARCHAR(20) | No |  | `STRING`, `NUMBER`, `BOOLEAN`, `JSON` |
| default_value_json | JSONB | Yes |  | |
| is_sensitive | BOOLEAN | No |  | |
| description | TEXT | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `ops.system_setting`

System-wide settings value.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| setting_definition_id | UUID | No | PK/FK -> ops.setting_definition.id | |
| setting_value_json | JSONB | No |  | |
| updated_by_account_id | UUID | Yes | FK -> iam.account.id | |
| updated_at | TIMESTAMPTZ | No |  | |

### `ops.account_setting`

Optional per-account or per-user override value for settings that do not belong in profile rows.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| account_id | UUID | No | PK/FK -> iam.account.id | composite PK part |
| setting_definition_id | UUID | No | PK/FK -> ops.setting_definition.id | composite PK part |
| setting_value_json | JSONB | No |  | |
| updated_at | TIMESTAMPTZ | No |  | |

Recommended settings include:

- registration enabled
- email verification required
- MFA required for admins
- MFA required for all users
- password policy (`auth.password.policy`) with length, character-mix, special-character, and username/email exclusion rules
- username change cooldown (`account.username.change_cooldown_seconds`)
- password history depth
- session idle timeout
- session absolute lifetime
- remember-me policy
- account deletion retention
- login rate-limit policy
- forgot-password rate-limit policy
- bootstrap admin creation flag
- maintenance mode
- passkey enablement policy
- geo/IP risk policy

### `ops.email_domain_rule`

Supports allow-list and block-list management with auditability.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| domain_name | VARCHAR(255) | No |  | normalized lowercase |
| rule_type | VARCHAR(20) | No |  | `ALLOW`, `BLOCK` |
| reason_text | TEXT | Yes |  | |
| created_by_account_id | UUID | Yes | FK -> iam.account.id | |
| created_at | TIMESTAMPTZ | No |  | |
| expires_at | TIMESTAMPTZ | Yes |  | optional temporary rule |

### `ops.audit_log`

Immutable operator and system audit log.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| actor_account_id | UUID | Yes | FK -> iam.account.id | null for system actions |
| action_code | VARCHAR(80) | No |  | |
| entity_type | VARCHAR(60) | No |  | |
| entity_id | UUID | Yes |  | |
| request_id | UUID | Yes |  | |
| idempotency_key_hash | CHAR(64) | Yes |  | |
| reason_text | TEXT | Yes |  | |
| old_value_json | JSONB | Yes |  | |
| new_value_json | JSONB | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `ops.security_event`

Authentication, abuse, and anomaly event log.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | Yes | FK -> iam.account.id | |
| session_id | UUID | Yes | FK -> auth.session.id | |
| ip_address | INET | Yes |  | |
| user_agent | TEXT | Yes |  | |
| severity | VARCHAR(20) | No |  | `info`, `warn`, `high`, `critical` |
| event_type | VARCHAR(60) | No |  | `LOGIN_FAILED`, `PASSWORD_RESET_USED`, `MFA_REMOVED` |
| request_id | UUID | Yes |  | |
| details_json | JSONB | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `ops.idempotency_key`

Supports retry-safe writes for sensitive endpoints.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| scope_code | VARCHAR(60) | No |  | endpoint or logical action name |
| account_id | UUID | Yes | FK -> iam.account.id | |
| key_hash | CHAR(64) | No |  | hash of client key |
| request_fingerprint_hash | CHAR(64) | No |  | prevent key reuse with different payload |
| response_status_code | INTEGER | Yes |  | |
| response_body_hash | CHAR(64) | Yes |  | optional |
| first_seen_at | TIMESTAMPTZ | No |  | |
| expires_at | TIMESTAMPTZ | No |  | |

Recommended constraint:

- unique `(scope_code, account_id, key_hash)`

### `ops.notification`

User-facing security or admin notification.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | No | FK -> iam.account.id | |
| notification_type | VARCHAR(40) | No |  | `security`, `admin_action`, `privacy` |
| event_code | VARCHAR(60) | No |  | |
| title | VARCHAR(200) | Yes |  | optional materialized title |
| payload_json | JSONB | No |  | |
| read_at | TIMESTAMPTZ | Yes |  | in-app read time |
| created_at | TIMESTAMPTZ | No |  | |

### `ops.notification_delivery`

Per-channel delivery record for email, in-app, SMS, or webhook.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| notification_id | UUID | No | FK -> ops.notification.id | |
| channel_type | VARCHAR(20) | No |  | `EMAIL`, `IN_APP`, `SMS`, `WEBHOOK` |
| destination_hash | CHAR(64) | Yes |  | avoid storing raw destination when possible |
| delivery_status | VARCHAR(20) | No |  | `queued`, `sent`, `failed`, `suppressed` |
| provider_message_id | VARCHAR(160) | Yes |  | |
| sent_at | TIMESTAMPTZ | Yes |  | |
| failed_at | TIMESTAMPTZ | Yes |  | |
| error_code | VARCHAR(80) | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `ops.notification_preference`

Optional user channel preferences for non-critical notices.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| account_id | UUID | No | PK/FK -> iam.account.id | composite PK part |
| event_code | VARCHAR(60) | No | PK | composite PK part |
| channel_type | VARCHAR(20) | No | PK | composite PK part |
| is_enabled | BOOLEAN | No |  | |
| updated_at | TIMESTAMPTZ | No |  | |

### `ops.security_report`

Supports "report suspicious login" and similar user-submitted security concerns.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| reporter_account_id | UUID | No | FK -> iam.account.id | |
| related_session_id | UUID | Yes | FK -> auth.session.id | |
| related_security_event_id | UUID | Yes | FK -> ops.security_event.id | |
| report_status | VARCHAR(20) | No |  | `open`, `reviewed`, `resolved` |
| description | TEXT | Yes |  | |
| resolved_by_account_id | UUID | Yes | FK -> iam.account.id | |
| resolved_at | TIMESTAMPTZ | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `ops.admin_action_approval`

Optional approval workflow for high-risk admin actions.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| action_code | VARCHAR(80) | No |  | |
| target_entity_type | VARCHAR(60) | No |  | |
| target_entity_id | UUID | Yes |  | |
| requested_by_account_id | UUID | No | FK -> iam.account.id | |
| approver_account_id | UUID | Yes | FK -> iam.account.id | |
| status | VARCHAR(20) | No |  | `pending`, `approved`, `rejected` |
| requested_at | TIMESTAMPTZ | No |  | |
| decided_at | TIMESTAMPTZ | Yes |  | |
| reason_text | TEXT | Yes |  | |

### `ops.admin_case`

Optional case container for support and moderation.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | Yes | FK -> iam.account.id | |
| case_type | VARCHAR(40) | No |  | `SECURITY`, `ABUSE`, `PRIVACY` |
| status | VARCHAR(20) | No |  | `open`, `in_review`, `closed` |
| created_by_account_id | UUID | No | FK -> iam.account.id | |
| assigned_to_account_id | UUID | Yes | FK -> iam.account.id | |
| created_at | TIMESTAMPTZ | No |  | |
| closed_at | TIMESTAMPTZ | Yes |  | |

### `ops.admin_case_note`

Optional case management notes.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| admin_case_id | UUID | No | FK -> ops.admin_case.id | |
| author_account_id | UUID | No | FK -> iam.account.id | |
| note_body | TEXT | No |  | |
| created_at | TIMESTAMPTZ | No |  | |

### `ops.admin_impersonation_session`

Optional admin impersonation with strict auditability.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| admin_account_id | UUID | No | FK -> iam.account.id | |
| target_account_id | UUID | No | FK -> iam.account.id | |
| reason_text | TEXT | No |  | |
| started_at | TIMESTAMPTZ | No |  | |
| ended_at | TIMESTAMPTZ | Yes |  | |

### `ops.outbox_event`

Optional event-bus or webhook outbox table.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| event_type | VARCHAR(80) | No |  | |
| aggregate_type | VARCHAR(60) | No |  | |
| aggregate_id | UUID | Yes |  | |
| payload_json | JSONB | No |  | |
| delivery_status | VARCHAR(20) | No |  | `pending`, `sent`, `failed` |
| created_at | TIMESTAMPTZ | No |  | |
| sent_at | TIMESTAMPTZ | Yes |  | |

## 5.4 `privacy` schema

### `privacy.retention_policy`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| entity_type | VARCHAR(60) | No |  | |
| retain_for_days | INTEGER | No |  | |
| action_after_retention | VARCHAR(20) | No |  | `DELETE`, `ANONYMIZE`, `ARCHIVE` |
| applies_after_field | VARCHAR(40) | No |  | `deleted_at`, `revoked_at`, `completed_at` |
| created_at | TIMESTAMPTZ | No |  | |
| updated_at | TIMESTAMPTZ | No |  | |

### `privacy.data_subject_request`

Generic privacy workflow row for export, erasure, rectification, or self-service deletion.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | Yes | FK -> iam.account.id | |
| request_type | VARCHAR(30) | No |  | `ACCESS_EXPORT`, `ERASURE`, `RECTIFICATION`, `ACCOUNT_DELETE` |
| status | VARCHAR(20) | No |  | `open`, `in_review`, `completed`, `rejected` |
| verified_by_account_id | UUID | Yes | FK -> iam.account.id | |
| export_file_asset_id | UUID | Yes | FK -> file.file_asset.id | optional export package |
| requested_at | TIMESTAMPTZ | No |  | |
| due_at | TIMESTAMPTZ | Yes |  | |
| completed_at | TIMESTAMPTZ | Yes |  | |
| notes | TEXT | Yes |  | |

### `privacy.legal_hold`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| entity_type | VARCHAR(60) | No |  | |
| entity_id | UUID | No |  | |
| reason | TEXT | No |  | |
| placed_by_account_id | UUID | Yes | FK -> iam.account.id | |
| placed_at | TIMESTAMPTZ | No |  | |
| released_at | TIMESTAMPTZ | Yes |  | |

### `privacy.consent_record`

Important when optional communications or privacy consent history is required.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | Yes | FK -> iam.account.id | nullable for guest consent |
| anonymous_subject_token_hash | CHAR(64) | Yes |  | |
| purpose_code | VARCHAR(60) | No |  | |
| notice_version_id | UUID | Yes | FK -> privacy.privacy_notice_version.id | |
| consent_status | VARCHAR(20) | No |  | `granted`, `withdrawn`, `denied` |
| captured_via | VARCHAR(20) | No |  | `web`, `mobile`, `api`, `support` |
| evidence_json | JSONB | Yes |  | |
| captured_at | TIMESTAMPTZ | No |  | |
| withdrawn_at | TIMESTAMPTZ | Yes |  | |

### `privacy.privacy_notice_version`

Optional notice version tracking.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| notice_type | VARCHAR(30) | No |  | `PRIVACY`, `COOKIE`, `TERMS` |
| version_label | VARCHAR(40) | No |  | |
| published_at | TIMESTAMPTZ | No |  | |
| retired_at | TIMESTAMPTZ | Yes |  | |

### `privacy.cookie_definition`

Optional cookie catalogue.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| cookie_name | VARCHAR(120) | No |  | |
| provider_name | VARCHAR(120) | Yes |  | |
| cookie_category | VARCHAR(30) | No |  | `ESSENTIAL`, `PREFERENCES`, `ANALYTICS`, `MARKETING` |
| is_strictly_necessary | BOOLEAN | No |  | |
| duration_seconds | BIGINT | Yes |  | |
| description | TEXT | Yes |  | |
| created_at | TIMESTAMPTZ | No |  | |
| retired_at | TIMESTAMPTZ | Yes |  | |

### `privacy.cookie_consent`

Optional current cookie preference snapshot.

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| account_id | UUID | Yes | FK -> iam.account.id | |
| anonymous_subject_token_hash | CHAR(64) | Yes |  | |
| notice_version_id | UUID | Yes | FK -> privacy.privacy_notice_version.id | |
| preferences_allowed | BOOLEAN | No |  | |
| analytics_allowed | BOOLEAN | No |  | |
| marketing_allowed | BOOLEAN | No |  | |
| captured_at | TIMESTAMPTZ | No |  | |
| updated_at | TIMESTAMPTZ | No |  | |
| withdrawn_at | TIMESTAMPTZ | Yes |  | |

## 5.5 `file` schema

This module is optional, but it is the cleanest way to support avatars, export bundles, and later security-related attachments.

### `file.storage_object`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| storage_provider | VARCHAR(30) | No |  | `s3`, `gcs`, `local` |
| bucket_name | VARCHAR(120) | No |  | |
| object_key | TEXT | No |  | |
| checksum_sha256 | CHAR(64) | No |  | |
| size_bytes | BIGINT | No |  | |
| created_at | TIMESTAMPTZ | No |  | |
| deleted_at | TIMESTAMPTZ | Yes |  | |

### `file.file_asset`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| storage_object_id | UUID | No | FK -> file.storage_object.id | |
| owner_account_id | UUID | Yes | FK -> iam.account.id | |
| original_filename | VARCHAR(255) | No |  | |
| mime_type | VARCHAR(120) | No |  | |
| purpose_code | VARCHAR(40) | No |  | `AVATAR`, `EXPORT_PACKAGE`, `EVIDENCE` |
| classification_code | VARCHAR(40) | No |  | `PUBLIC`, `INTERNAL`, `CONFIDENTIAL` |
| created_at | TIMESTAMPTZ | No |  | |
| deleted_at | TIMESTAMPTZ | Yes |  | |

### `file.file_attachment`

| Column | Type | Null | Key | Notes |
|---|---|---:|---|---|
| id | UUID | No | PK | |
| file_asset_id | UUID | No | FK -> file.file_asset.id | |
| entity_type | VARCHAR(60) | No |  | |
| entity_id | UUID | No |  | |
| attachment_role | VARCHAR(40) | No |  | `AVATAR`, `EXPORT_RESULT`, `CASE_EVIDENCE` |
| created_at | TIMESTAMPTZ | No |  | |

## 6. How the recommended account states are represented

The scope lists these recommended states:

- `pending`
- `awaiting_setup`
- `active`
- `email_unverified`
- `password_reset_required`
- `suspended`
- `frozen`
- `deleted`

For robustness, do not store all of them as one overloaded enum. Represent them like this:

| Effective state | How to derive it |
|---|---|
| `pending` | `iam.account.status_code = 'pending'` |
| `awaiting_setup` | `iam.account.status_code = 'awaiting_setup'`; login is allowed so the frontend can route the user to setup |
| `active` | `iam.account.status_code = 'active'` and no active blocking restriction |
| `email_unverified` | active account whose primary login email is not verified |
| `password_reset_required` | active account whose `auth.password_credential.must_rotate = true` |
| `suspended` | active `iam.account_restriction` row with `restriction_type = 'suspend'` |
| `frozen` | active `iam.account_restriction` row with `restriction_type = 'freeze'` |
| `deleted` | `iam.account.status_code = 'deleted'` and `deleted_at` is not null |

This keeps lifecycle state, verification state, and temporary restrictions from conflicting with each other.

## 7. Scope coverage map

This section maps the feature scope directly to the schema so the design covers mandatory, important, and optional features.

| Scope area | Functions covered | Main tables |
|---|---|---|
| Account lifecycle | register, activate, login, logout, refresh, deactivate, freeze, restore, soft delete, self-service deletion request, admin-created awaiting-setup account, forced password reset, forced re-verification, anonymous draft, invite-only, staged approval | `iam.account`, `iam.account_status_history`, `iam.account_restriction`, `auth.password_credential`, `auth.session`, `auth.email_verification_challenge`, `privacy.data_subject_request`, `auth.registration_draft`, `auth.registration_invite`, `auth.registration_approval` |
| Identity and contact | primary email, email verification, change email, normalized lookup, unique email rules, multiple emails, backup email, login-enabled flags, resend verification, dual-confirm email change, phone, locale, timezone, display name, avatar | `iam.account_email`, `auth.email_verification_challenge`, `auth.account_email_change_request`, `iam.account_phone`, `auth.phone_verification_challenge`, `iam.account_profile`, `file.file_asset` |
| Password and credentials | password registration, change, forgot/reset, token flow, Argon2id, per-password salt, complexity rules, password history, breach flag, expiry/rotation policy, credential enrollment audit, passkeys, external identity providers, passwordless | `auth.authenticator`, `auth.password_credential`, `auth.password_history`, `auth.password_reset_challenge`, `auth.passkey_credential`, `auth.external_identity`, `ops.audit_log`, `ops.security_event`, `ops.system_setting` |
| Authentication and session control | session creation, refresh, revoke, logout current device, logout all devices, hashed tokens, active session list, device label, user agent, IP, idle timeout, absolute lifetime, remember-me, concurrent session limit, trusted device, high-risk approval, step-up auth | `auth.session`, `auth.trusted_device`, `auth.login_challenge`, `ops.system_setting`, `ops.security_event` |
| MFA / 2FA / recovery | TOTP, recovery codes, enable/disable 2FA, verify at login, revoke lost factor, force MFA for admins/all users/by role, backup method, suspicious recovery alert, passkey as MFA, SMS fallback | `auth.authenticator`, `auth.totp_factor`, `auth.recovery_code_set`, `auth.recovery_code`, `auth.passkey_credential`, `auth.passkey_registration_challenge`, `auth.passkey_authentication_challenge`, `auth.sms_factor`, `ops.notification`, `ops.notification_delivery`, `ops.system_setting` |
| User self-service security | view account status, complete setup, change password, change primary email, recent login/activity history, revoke own sessions, recovery code regeneration, see MFA methods, security notifications, suspicious login report, export/privacy requests | `iam.account`, `iam.account_status_history`, `auth.session`, `ops.security_event`, `auth.authenticator`, `auth.recovery_code_set`, `ops.notification`, `ops.security_report`, `privacy.data_subject_request` |
| Account restriction model | pending, awaiting setup, active, suspended, frozen, deleted, freeze temporarily, suspend with reason, restore, require password reset, revoke sessions, disable login | `iam.account`, `iam.account_status_history`, `iam.account_restriction`, `auth.password_credential`, `auth.session`, `ops.audit_log` |
| Admin portal | permission-scoped admin access, roles/permissions, custom role creation/editing/deletion, invitation management, user search/filter, user detail, freeze/unfreeze, suspend/restore, soft delete/recover, force logout, reset credentials, verify email, bulk actions, assign roles with optional expiry, required reason, audit trail, security events, active sessions, impersonation, approval workflow, case notes | `iam.role`, `iam.permission`, `iam.role_permission`, `iam.account_role`, `iam.account`, `iam.account_restriction`, `auth.registration_invite`, `auth.session`, `ops.audit_log`, `ops.security_event`, `ops.admin_impersonation_session`, `ops.admin_action_approval`, `ops.admin_case`, `ops.admin_case_note` |
| System settings and policy | registration toggle, email verification required, MFA policies, password policy, lockout policy, session policy, deletion policy, allowed/blocked email domains, invite-only mode, bootstrap admin flag, passkey enablement, geo/IP risk, maintenance mode | `ops.setting_definition`, `ops.system_setting`, `ops.email_domain_rule`, `auth.registration_invite` |
| Security monitoring and risk controls | failed login tracking, rate limiting, lockout, IP capture, request ID, suspicious event logging, admin action audit, device fingerprint, impossible travel, new-IP alert, credential stuffing detection, brute-force detection, reset abuse detection, adaptive challenge, risk scoring, TOR/proxy heuristics | `ops.security_event`, `auth.account_lockout`, `auth.login_challenge`, `auth.session`, `ops.audit_log`, `ops.notification`, `ops.outbox_event` |
| Error handling and logging | stable codes, request correlation, safe logs, separate audit/security logs, severity levels, taxonomy, operator diagnostics, retry-safe idempotency | `ops.audit_log`, `ops.security_event`, `ops.idempotency_key` |
| Notifications | verification mail, reset mail, login alert, password change notice, MFA change notice, new device alert, suspicious login alert, freeze/restore notice, admin action notice, in-app notifications, webhook/event-bus notifications | `ops.notification`, `ops.notification_delivery`, `ops.notification_preference`, `ops.outbox_event` |
| Privacy, retention, governance | soft deletion, retention for deleted accounts and sessions, data minimization, consent records, legal hold, export request, erasure request, cookie consent, privacy notice versioning, full data-subject workflow, published legal documents | `iam.account`, `privacy.legal_document`, `privacy.retention_policy`, `privacy.data_subject_request`, `privacy.legal_hold`, `privacy.consent_record`, `privacy.privacy_notice_version`, `privacy.cookie_definition`, `privacy.cookie_consent` |

## 8. Key indexes and constraints

Recommended high-value indexes:

- `iam.account_email(normalized_email)` filtered to active rows
- one active primary email per account
- `iam.account_phone(e164_phone_number)` filtered to active login-enabled rows
- `auth.registration_invite(invite_code_hash)` unique
- `iam.account_role(account_id, expires_at)` for active role lookup and expiry cleanup
- `iam.account_status_history(account_id, changed_at desc)`
- `iam.account_restriction(account_id, status_code, ends_at)`
- `auth.authenticator(account_id, authenticator_type, status)`
- `auth.session(account_id, absolute_expires_at desc)`
- `auth.session(device_fingerprint_hash)` if trusted-device features are enabled
- `auth.password_history(account_id, password_version desc)`
- `auth.email_verification_challenge(account_email_id, expires_at desc)`
- `auth.password_reset_challenge(account_id, expires_at desc)`
- `auth.account_lockout(subject_type, subject_key_hash, locked_until)`
- `ops.system_setting(updated_at desc)`
- `ops.audit_log(entity_type, entity_id, created_at desc)`
- `ops.audit_log(request_id)`
- `ops.security_event(account_id, created_at desc)`
- `ops.security_event(ip_address, created_at desc)`
- `ops.notification(account_id, created_at desc)`
- `ops.notification_delivery(notification_id, channel_type, created_at desc)`
- `privacy.data_subject_request(account_id, requested_at desc)`
- `privacy.retention_policy(entity_type)`

Recommended hard constraints:

- unique active primary login email per account
- unique active password authenticator per account
- unique `(provider_code, provider_subject)` in external identities
- unique `(scope_code, account_id, key_hash)` for idempotency
- unique `(recovery_code_set_id, sequence_number)` for recovery code order
- check `digits in (6, 8)` for TOTP
- check `password_version > 0`
- check `absolute_expires_at >= idle_expires_at` for sessions

Example partial unique index:

```sql
create unique index uq_account_email_primary_active
    on iam.account_email (account_id)
    where is_primary_for_account = true and deleted_at is null;
```

Example idempotency index:

```sql
create unique index uq_idempotency_scope_account_key
    on ops.idempotency_key (scope_code, account_id, key_hash);
```

## 9. Transaction boundaries for critical flows

These flows should be single transactions in the application service layer.

### Registration

Write together:

- `iam.account`
- `iam.account_profile`
- `iam.account_email`
- `auth.authenticator`
- `auth.password_credential`
- `iam.account_status_history`
- `auth.email_verification_challenge`
- `ops.audit_log`
- `ops.security_event`

### Email change

Write together:

- `auth.account_email_change_request`
- old/new `auth.email_verification_challenge` rows
- `ops.audit_log`
- `ops.security_event`

Complete together after both confirmations:

- insert new `iam.account_email`
- switch primary flag if requested
- soft delete or disable old email when policy says so
- write `ops.audit_log`

### Password change

Write together:

- copy old row into `auth.password_history`
- update `auth.password_credential`
- optionally revoke sessions according to policy
- write `ops.audit_log`
- write `ops.security_event`
- create `ops.notification`

### Login with MFA

Write together:

- read password or external identity
- create `auth.login_challenge` if MFA or step-up is required
- once satisfied, create `auth.session`
- update `iam.account.last_login_at`
- write `ops.security_event`

### Freeze or suspend account

Write together:

- insert `iam.account_restriction`
- update `iam.account.status_code` only if policy requires a lifecycle change
- revoke matching `auth.session` rows when required
- insert `iam.account_status_history` when status changes
- write `ops.audit_log`
- write `ops.security_event`
- create `ops.notification`

## 10. Operational notes

- Use UTC timestamps everywhere.
- Use prepared statements only. Do not build SQL from request strings.
- Normalize email before lookup and before uniqueness checks.
- Hash session and refresh tokens before insert.
- Never log raw passwords, reset tokens, OTP secrets, recovery codes, or webhook secrets.
- Partition or archive `ops.audit_log` and `ops.security_event` once volume grows.
- Keep cache-backed rate limits for hot auth endpoints even if SQL stores lockout history.
- Put large JSON detail into `details_json`, but keep the event type and actor columns queryable.
- Add scheduled cleanup jobs for expired challenges, expired sessions, replaced recovery code sets, and retention-policy execution.

## 11. Suggested rollout order

### Phase 1: core MVP

- account and profile
- emails and email verification
- password credentials and password reset
- sessions and logout/revoke
- roles and permissions
- admin freeze/restore
- system settings
- audit log and security events

### Phase 2: hardening

- TOTP
- recovery codes
- password history and rotation
- account lockout and login challenges
- notification delivery
- consent record and deletion/export workflow

### Phase 3: optional platform features

- multiple phones
- passkeys
- external identity providers
- trusted devices
- invite-only and approval flows
- impersonation, approval workflow, and case notes
- cookie/notice tracking
- shared file module for avatars and export packages

## 12. Final recommendation

The most robust version of this design is not the one with the fewest tables. It is the one that keeps each security-critical fact in the right place:

- current account state in `iam.account`
- state transitions in `iam.account_status_history`
- temporary restrictions in `iam.account_restriction`
- credentials in typed auth tables
- hashed tokens and codes, encrypted reusable secrets
- sessions as first-class rows
- admin actions in `ops.audit_log`
- risky behavior in `ops.security_event`
- policy in `ops.system_setting`
- retention and privacy in `privacy.*`

That structure gives you clean SQL, safer security behavior, easier admin tooling, and room to add optional features later without reworking the core tables.
