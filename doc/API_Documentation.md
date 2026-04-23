# Core User Management API Documentation

The canonical API contract is [API_Documentation.openapi.yaml](API_Documentation.openapi.yaml).

Implementation note:

- the Rust backend in this repository also exposes signed local transport helpers under `/internal/uploads/*` and `/internal/files/*`
- those internal routes make the documented file-intent flow runnable in local development without requiring an external object store
- they are implementation details, not part of the stable public API contract

Error note:

- API error payloads include `error.urgencyLevel` on a 1-9 scale so clients and operators can distinguish low-friction request fixes from higher-urgency backend failures
- see [Error_Handling_Guide.md](Error_Handling_Guide.md) for the urgency scale, local log path, and common recovery steps

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
- admin roles, security events, audit logs, and per-user session/security inspection

If this Markdown guide and the OpenAPI file ever disagree, treat [API_Documentation.openapi.yaml](API_Documentation.openapi.yaml) as the source of truth.
