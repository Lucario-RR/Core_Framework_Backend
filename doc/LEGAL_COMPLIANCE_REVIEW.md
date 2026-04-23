# Legal and Compliance Review

This review is based on the documentation and reference API contract in this repository, not on a running implementation.

That means:

- it can identify likely compliance gaps in the designed modules
- it cannot certify real compliance without checking the deployed frontend, backend, logging, storage, retention jobs, and legal texts
- it is not legal advice

## Overall view

The contract is already privacy-aware in several good ways:

- legal document version capture exists
- cookie preference storage exists
- public and private data are separated better than in the older draft
- file upload is private-by-default and uses signed URLs
- passkeys, MFA, and session security are designed reasonably

However, I would not call the platform legally ready for UK, EU, and US production yet.

The main reason is that the contract covers consent recording, but it does not yet expose a full privacy-rights workflow for access, export, deletion, and correction, even though the scope and database guides clearly expect one.

## Modules with likely compliance gaps

### 1. Privacy rights module

Status: **Not complete enough for UK/EU/US privacy launch**

Why this matters:

- UK GDPR and EU GDPR require practical ways to handle access, deletion, rectification, and in many cases data portability.
- US state privacy laws also expect consumer request handling, especially access and deletion workflows.

What is present:

- `GET /legal/documents`
- `GET /me/privacy-consents`
- `POST /me/privacy-consents`
- `GET /privacy/cookie-preferences`
- `PUT /privacy/cookie-preferences`

What is missing from the API contract:

- account deletion request endpoint
- data export request endpoint
- erasure request endpoint
- rectification or correction request endpoint
- request-status tracking for privacy requests

Why I am confident this is a real gap:

- `doc/core_user_system_scope.md` says the core should support account export, privacy request submission, and account erasure workflows.
- `doc/Database_Guide.md` includes `privacy.data_subject_request`, `privacy.retention_policy`, and related privacy tables.
- the OpenAPI file does not expose an equivalent user-facing privacy request API.

Recommendation:

- add a privacy request resource such as `/me/privacy-requests`
- support request types like `ACCESS_EXPORT`, `ERASURE`, `RECTIFICATION`, and `ACCOUNT_DELETE`
- expose status, requested time, due time, and completion outcome
- make file exports and account deletion connect to the same workflow

### 2. Admin bootstrap registration module

Status: **Must not be enabled in production**

Why this matters:

- a public admin bootstrap route is a severe security and governance risk
- weak production hardening around admin creation can create exposure under GDPR/UK GDPR security duties and US unfair or inadequate security enforcement theories

What is present:

- `POST /auth/register-admin`

Why this is a risk:

- the OpenAPI description itself says it is setup-only, should be gated behind a flag, and should be removed before stricter production release

Recommendation:

- disable it outside local setup or first-run install
- require a deployment-time secret, console-only bootstrap, or one-time migration flow instead
- do not expose it in public frontend navigation at all

### 3. Cookie compliance module

Status: **Partially covered, but not enough by itself for UK/EU cookie rules**

Why this matters:

- UK PECR and EU ePrivacy-style rules generally require prior consent before non-essential analytics or marketing cookies are set
- recording a preference is not the same as enforcing it

What is present:

- cookie preference read and write endpoints
- versioned legal documents including cookie policy

What is still missing or unclear:

- no cookie catalogue endpoint for transparency
- no evidence in this repo that analytics and marketing storage are blocked until consent
- no explicit withdrawal-history or consent-proof workflow beyond the current snapshot

Recommendation:

- treat the current cookie API as necessary but not sufficient
- block non-essential cookies until `analytics` or `marketing` are explicitly true
- consider exposing a cookie inventory or policy metadata endpoint if the frontend needs to render categories from the backend

### 4. File and receipt governance module

Status: **Strong security direction, but privacy lifecycle is incomplete**

Why this matters:

- receipts can contain personal data, location data, transaction details, and sometimes third-party data
- UK/EU/US privacy compliance depends on retention, deletion, and subject-right handling, not just secure upload

What is good:

- signed uploads
- private-by-default storage model
- explicit file purposes
- metadata stripping support

What is missing at API level:

- user-facing retention/deletion policy visibility
- clear privacy-request linkage for uploaded receipts
- export and erasure workflow exposure for private attachments

Recommendation:

- connect file assets to the missing privacy request workflow
- define retention periods for orphaned, rejected, deleted, and export-related files
- ensure download URLs are short-lived and never logged

### 5. Alerts, phone, and communications module

Status: **Conditionally risky**

Why this matters:

- if alerts are delivered by SMS or marketing-style email, UK PECR, EU ePrivacy, and US communications rules such as TCPA can apply
- user-requested service alerts are usually easier to justify than promotional messaging, but consent boundaries still need to be clear

What is present:

- watchlist and alert endpoints
- phone number storage and verification

What is unclear:

- no notification-preference API in the OpenAPI contract
- no explicit distinction between service alerts and marketing messages
- no channel-specific opt-in or opt-out workflow in the API contract

Recommendation:

- separate service-alert consent from marketing consent
- require explicit channel selection and opt-in if SMS is introduced
- keep price alerts transactional and user-requested unless legal review approves broader messaging

### 6. Generic admin database table module

Status: **High governance risk if too broad**

Why this matters:

- a generic admin CRUD surface can easily overexpose personal data or allow edits outside clear purpose limits
- GDPR/UK GDPR data minimization and access control duties become harder to satisfy if this surface is not tightly curated

What is good:

- the contract describes curated tables, lookup metadata, and admin-only access

What still needs care:

- tight allowlists for exposed tables and fields
- masking or omission of sensitive fields
- full audit for reads where policy requires it, and definitely for writes
- role-based separation between ordinary admin, moderator, and security operations

Recommendation:

- keep this module limited to explicitly curated resources only
- never expose unrestricted raw table browsing for IAM, auth, session, receipt, or privacy tables

## Areas that look directionally sound

These areas do not show an obvious legal blocker in the contract itself:

- password, MFA, session, and passkey architecture
- separation between public price reads and private purchase evidence
- consent version capture during registration
- use of private file uploads instead of public receipt URLs

Important nuance on passkeys:

- passkey and WebAuthn support does not automatically mean the server is collecting biometric data
- normally the device handles the biometric step locally and the server stores credential material, not the user's fingerprint or face scan
- that said, notices and internal records should still describe the authentication method accurately

## Recommended next changes before calling this compliant

1. Add privacy request APIs for access, export, erasure, rectification, and account deletion.
2. Remove or hard-disable `/auth/register-admin` in any production profile.
3. Treat cookie preferences as enforcement inputs, not just stored settings.
4. Add retention and deletion rules for files, receipts, soft-deleted user data, and security logs.
5. Separate service-alert consent from marketing consent, especially for phone-based messaging.
6. Lock down generic admin table access to a strict allowlist with redaction and audit.

## Bottom line

Yes, there are modules that are not yet safe to describe as legally complete for UK/EU/US use.

The clearest ones are:

- the privacy rights module
- the admin bootstrap route
- the cookie module if non-essential cookies are set before consent

The file, alerts, and generic admin CRUD modules also need tighter policy and workflow coverage before launch.
