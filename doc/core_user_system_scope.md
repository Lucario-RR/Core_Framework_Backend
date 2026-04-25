# Core User System Scope

This document defines a reusable backend core for Rust projects that only need account, login, security, and admin control features.

It is intentionally focused on identity and access management, not business-domain features.

The ideas here are aligned with the existing reference material in:

- `doc/Database_Guide.md`
- `doc/API_Documentation.md`

## 1. Scope Principles

The core system should include only what is necessary to create, secure, control, and audit user accounts.

Included:

- registration and login
- password and credential management
- email ownership and verification
- session and device control
- 2FA / MFA and recovery
- account freeze / restore / delete
- admin control and policy settings
- security events, audit logs, and operational alerts

Not in core by default:

- business-domain profile data
- social features
- billing and subscription
- shopping, catalog, or order data
- analytics unrelated to security or account operations

## 2. Functional Categories

### 2.1 Account Lifecycle

These are the basic account-state functions.

Must-have:

- register account
- activate account
- login
- logout
- refresh session
- deactivate account
- freeze account
- restore account
- soft delete account

Important:

- self-service account deletion request
- admin-created account
- forced password reset on next login
- forced re-verification of contact details

Optional:

- anonymous pre-registration draft
- invite-only registration
- staged approval before activation

### 2.2 Identity and Contact Management

This category proves who the user is and how the system can reach them.

Must-have:

- primary email address
- email verification
- change email
- normalized email lookup
- unique email rules

Important:

- multiple email addresses per account
- secondary or backup email
- login-enabled or non-login email flags
- email verification resend
- email change confirmation on both old and new address

Optional:

- phone number support
- verified backup phone
- region or locale preference
- timezone preference
- display name
- avatar

### 2.3 Password and Credential Management

This is the most important security area.

Must-have:

- password set on registration
- password change
- forgot password flow
- password reset token flow
- password hashing with Argon2id
- unique random salt per password
- password complexity rules
- password history to prevent reuse

Important:

- password breach or compromise flag
- password expiry only when policy requires it
- admin force password rotation
- credential enrollment audit

Optional:

- passkeys
- external identity providers
- passwordless login

### 2.4 Authentication and Session Control

This controls authenticated access after credentials are accepted.

Must-have:

- session creation
- session refresh
- session revocation
- logout from current device
- logout from all devices
- secure session cookie or token handling
- token hash storage instead of raw token storage

Important:

- list active sessions
- show device label, user agent, IP, and last seen time
- session idle timeout
- absolute session lifetime
- remember-me policy
- concurrent session limit

Optional:

- trusted device model
- session approval for high-risk login
- step-up authentication for sensitive actions

### 2.5 MFA / 2FA / Recovery

This is strongly recommended, especially for admin access.

Must-have:

- TOTP 2FA support
- recovery codes
- enable or disable 2FA
- verify 2FA during login
- revoke lost factor

Important:

- require or recommend 2FA enrollment for newly registered admins
- require or recommend 2FA enrollment globally or by role at account creation
- backup recovery method
- suspicious recovery event notification

Optional:

- passkey as MFA or primary auth
- SMS fallback if the project truly needs it

### 2.6 User Self-Service Security

These functions reduce support cost and improve trust.

Must-have:

- view account status
- change password
- change primary email
- view recent login activity
- revoke own sessions

Important:

- download recovery codes again after regeneration
- see enrolled MFA methods
- security notifications
- report suspicious login

Optional:

- account export
- privacy request submission

### 2.7 Account Status and Restriction Model

The system should distinguish several account states instead of a single active flag.

Recommended states:

- `pending`
- `active`
- `email_unverified`
- `password_reset_required`
- `suspended`
- `frozen`
- `deleted`

Recommended admin actions:

- freeze account temporarily
- suspend account with reason
- restore account
- require password reset
- revoke sessions
- disable login
- disable registration for the user after abuse

### 2.8 Admin Portal

The admin portal is a first-class part of the core system.

Must-have:

- admin login
- admin roles and permissions
- user search and filtering
- view one user profile
- freeze and unfreeze user
- suspend and restore user
- soft delete and recover user where policy allows
- force logout user
- reset or invalidate credentials
- verify or unverify email

Important:

- create user or admin account
- bulk user actions
- assign roles
- change account state with required reason
- see audit trail per user
- see security events per user
- see active sessions per user

Optional:

- impersonation with strict audit
- approval workflow for high-risk admin actions
- case management notes

### 2.9 System Settings and Policy Management

This is where the admin portal becomes reusable across projects.

Must-have:

- toggle user registration on or off
- toggle email verification requirement
- toggle 2FA requirement for admins
- password policy settings
- lockout and retry settings
- session timeout settings
- account deletion policy

Important:

- require or recommend 2FA enrollment for newly registered users
- allowed email domains
- blocked email domains
- login rate-limit policy
- forgot-password rate-limit policy
- invite-only registration mode
- bootstrap admin creation flag for setup only

Optional:

- passkey enablement policy
- geo or IP risk policy
- maintenance or read-only mode

### 2.10 Security Monitoring and Risk Controls

This is essential for a reusable framework, not an afterthought.

Must-have:

- failed login tracking
- rate limiting by IP and account
- lockout or exponential backoff
- IP capture on register and login
- request ID on every request
- suspicious event logging
- admin action audit log

Important:

- device fingerprint or device label
- impossible-travel or location anomaly checks
- new-IP login alert
- credential stuffing detection
- brute-force detection
- password reset abuse detection

Optional:

- adaptive challenge or CAPTCHA
- risk-scored login decisions
- ASN, TOR, proxy, or datacenter heuristics

### 2.11 Error Handling and Logging

The core system must return safe errors to clients and rich events internally.

Must-have:

- structured error response
- stable error codes
- validation errors by field
- authentication and authorization errors
- conflict and rate-limit errors
- correlation via request ID
- redaction of passwords, tokens, and secret values in logs

Important:

- separate audit log and security event log
- severity levels
- event type taxonomy
- operator-facing diagnostics
- retry-safe idempotent write handling for sensitive actions

Recommended error groups:

- `VALIDATION_ERROR`
- `UNAUTHORIZED`
- `FORBIDDEN`
- `NOT_FOUND`
- `CONFLICT`
- `RATE_LIMITED`
- `ACCOUNT_FROZEN`
- `EMAIL_NOT_VERIFIED`
- `PASSWORD_RESET_REQUIRED`
- `MFA_REQUIRED`
- `MFA_INVALID`
- `SECURITY_CHALLENGE_REQUIRED`

### 2.12 Notifications

The system should notify users when important security events happen.

Must-have:

- email verification message
- password reset message
- login alert for sensitive events
- password changed notification
- MFA enabled or removed notification

Important:

- new device login notification
- suspicious login alert
- account frozen or restored notification
- admin action notification where appropriate

Optional:

- in-app notifications
- webhook or event-bus notifications

### 2.13 Privacy, Retention, and Data Governance

This is useful if the framework will be reused across projects.

Must-have:

- soft deletion support
- retention policy for deleted accounts and sessions
- data minimization
- sensitive field redaction in logs

Important:

- consent record for optional communications
- legal hold support
- account export request
- account erasure request workflow

Optional:

- cookie consent records
- privacy notice versioning
- full data-subject request workflow

## 3. Recommended Priorities

### Phase 1: Core MVP

Build these first:

- account
- account email
- registration
- login/logout/refresh
- password hashing and password change
- forgot/reset password
- session management
- admin roles
- admin user freeze and restore
- audit log
- security event log
- system settings for registration, password, and session policy

### Phase 2: Security Hardening

Add next:

- TOTP 2FA
- recovery codes
- active session list and remote revoke
- password history and reuse prevention
- force password reset
- require or recommend 2FA enrollment for new admins
- rate-limiting and lockout policy
- IP and device tracking

### Phase 3: Reusable Platform Features

Add when you want this to serve many projects:

- multiple emails
- account phone
- passkeys
- external identity providers
- privacy workflows
- event-driven notifications
- richer admin policy management

## 4. Suggested Admin Portal Sections

Recommended admin portal navigation:

- Overview
- Users
- Roles and Permissions
- Security Events
- Audit Log
- Sessions
- System Settings
- Notifications

Recommended `Users` page actions:

- search by email, ID, display name, status, role, and created date
- freeze, suspend, restore, delete, and reactivate
- reset password
- revoke sessions
- mark email verified
- require MFA enrollment
- require password change

Recommended `System Settings` groups:

- registration
- authentication
- password policy
- MFA policy
- session policy
- account lifecycle
- rate limiting
- notification templates
- security monitoring thresholds

## 5. Suggested Rust Backend Modules

Recommended crate or module boundaries:

- `account`
- `auth`
- `credential`
- `session`
- `mfa`
- `admin`
- `policy`
- `audit`
- `security_event`
- `notification`
- `common_error`

Recommended shared concerns:

- request validation
- authorization guard
- structured logging
- database transaction helpers
- clock abstraction for testing
- idempotency support for critical writes

## 6. Suggested Database Building Blocks

Aligned with the reference schema, the user-management core should at least have:

- `account`
- `account_profile`
- `account_email`
- `authenticator`
- `password_credential`
- `password_history`
- `session`
- `role`
- `permission`
- `role_permission`
- `account_role`
- `system_setting`
- `audit_log`
- `security_event`
- `account_suspension`
- `notification`

Recommended additions once MFA is added:

- `totp_factor`
- `recovery_code_set`
- `recovery_code`
- `passkey_credential`

Useful token or challenge tables if you want strong lifecycle control:

- `email_verification_challenge`
- `password_reset_challenge`
- `login_challenge`

## 7. Suggested API Groups

Recommended route groups:

- `/auth/*`
- `/me/*`
- `/me/security/*`
- `/admin/users/*`
- `/admin/security/*`
- `/admin/settings/*`
- `/admin/roles/*`

Example core endpoints:

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `POST /auth/password/forgot`
- `POST /auth/password/reset`
- `POST /auth/password/change`
- `POST /auth/mfa/totp/enroll`
- `POST /auth/mfa/totp/verify`
- `POST /auth/mfa/recovery/use`
- `GET /me`
- `PATCH /me`
- `GET /me/sessions`
- `DELETE /me/sessions/{sessionId}`
- `GET /me/security/events`
- `GET /admin/users`
- `PATCH /admin/users/{accountId}`
- `POST /admin/users/bulk-actions`
- `GET /admin/security/events`
- `GET /admin/settings`
- `PATCH /admin/settings/{settingKey}`

## 8. Practical Security Rules

These should be treated as design requirements.

- use Argon2id for passwords
- generate a unique salt per password
- never log passwords, tokens, OTP secrets, or recovery codes
- store refresh or session tokens only as hashes
- require MFA enrollment for new admin accounts, but do not block an existing login solely because no factor has been enrolled
- record register/login IP and user agent
- audit every admin write
- create a security event for failed login, password reset, MFA change, session revoke, and account freeze
- return safe client errors, but keep full details in internal logs
- avoid putting secrets in query strings

## 9. Recommended Boundary Between Core and Future Project Modules

Keep in core:

- account identity
- authentication
- authorization
- sessions
- MFA
- admin policy control
- audit and security logging
- notifications related to account security

Keep outside core unless truly shared:

- business profile fields
- product-specific permissions
- domain-specific dashboards
- billing
- CRM
- content management

## 10. Final Recommendation

If this framework is meant to power future projects, the best shape is:

1. a small but strong account and auth core
2. a policy-driven admin portal
3. separate audit and security-event logging
4. MFA-ready credential architecture from day one
5. reusable settings and status models instead of hard-coded booleans

The highest-value features for your first implementation are:

- email-based registration and login
- Argon2id password storage with per-password salt
- password reset and change flows
- session and device revocation
- admin freeze and restore
- require or recommend 2FA enrollment for new admins
- structured errors
- audit logs and security events
- configurable system settings
