# Error Handling Guide

This file explains the API error urgency scale, where debug logs are written locally, and what to do when common error responses appear.

## Urgency Scale

Every API error response now includes `error.urgencyLevel` on a 1-9 scale.

- `1`: informational edge case, usually safe to ignore or retry later
- `2`: low urgency resource/state issue, usually a bad ID or missing record
- `3`: user input problem that should be fixed client-side before retrying
- `4`: session or request precondition problem that usually needs a refresh, new token, or retry flow
- `5`: permission or state conflict that usually needs a user/admin decision
- `6`: throttling or security-hardening response that should pause retries
- `7`: serious service issue that should be investigated soon
- `8`: high urgency backend failure that needs operator attention
- `9`: critical incident level reserved for severe security, data-integrity, or infrastructure emergencies

## Local Debug Log

The backend writes a local debug log to:

- `logs/backend-debug.log`

You can change the log directory with:

- `LOG_DIR`

The log captures:

- request/response tracing from the HTTP stack
- API errors including `requestId`, `code`, and `urgencyLevel`
- startup and server lifecycle messages

## Common Errors

### `VALIDATION_ERROR` (`urgencyLevel: 3`)

Meaning:

- The request body, query, or headers did not satisfy the API contract.

What to do:

- Check `error.details` for the field name when present.
- Re-read the matching request schema in `doc/API_Documentation.openapi.yaml`.
- Fix formatting issues like invalid email, UUID, phone, or password length.

Typical examples:

- missing `Idempotency-Key`
- invalid `verificationToken`
- malformed `primaryPhone`

### `UNAUTHORIZED` (`urgencyLevel: 4`)

Meaning:

- The caller is not authenticated, the bearer token is invalid, the refresh cookie is missing, or CSRF validation failed.

What to do:

- Log in again and refresh the session.
- If using refresh, send both the refresh cookie and `X-CSRF-Token`.
- Make sure the `Authorization` header is exactly `Bearer <token>`.

Typical examples:

- expired or revoked session
- missing CSRF header on refresh
- invalid MFA challenge verification attempt

### `FORBIDDEN` (`urgencyLevel: 5`)

Meaning:

- The caller is authenticated but not allowed to do the action.

What to do:

- Check account state and role assignments.
- For admin endpoints, confirm the account has the `admin` role.
- Check whether registration or passkeys were disabled by system settings.
- Check for account restrictions such as freeze, suspend, or login disablement.

### `NOT_FOUND` (`urgencyLevel: 2`)

Meaning:

- The resource does not exist, is deleted, or does not belong to the caller.

What to do:

- Verify the identifier came from a fresh response.
- Check that the resource belongs to the authenticated account.
- Confirm the record was not soft-deleted or revoked.

Typical examples:

- unknown `fileId`
- deleted `emailId`
- revoked `sessionId`

### `CONFLICT` (`urgencyLevel: 5`)

Meaning:

- The request collides with current system state.

What to do:

- Do not blindly retry.
- Re-fetch the current state, then decide the next step.
- For email or phone changes, check whether the target already exists.
- For reset or verification flows, assume the token/code may be stale or already used.

Typical examples:

- email already exists
- password reset token is stale
- email is not verified yet, so it cannot become primary

### `PRECONDITION_FAILED` (`urgencyLevel: 4`)

Meaning:

- Optimistic concurrency failed because the resource changed after the client last read it.

What to do:

- Re-fetch the resource.
- Use the latest `ETag` value in `If-Match`.
- Reapply the user edits on top of the latest version.

### `RATE_LIMITED` (`urgencyLevel: 6`)

Meaning:

- The backend is intentionally slowing or blocking repeated attempts.

What to do:

- Stop retrying immediately.
- Wait before the next attempt.
- Check whether the user triggered login or reset protections.
- If this happens unexpectedly, inspect `logs/backend-debug.log` with the returned `requestId`.

### `INTERNAL_ERROR` (`urgencyLevel: 8`)

Meaning:

- The backend failed while handling the request.

What to do:

- Look up the `requestId` in `logs/backend-debug.log`.
- Check database connectivity and whether migrations ran successfully.
- Check file storage permissions for `storage/` and log directory permissions for `logs/`.
- Check required environment variables such as `DATABASE_URL`, `JWT_SECRET`, and `APP_BASE_URL`.

## Recommended Debug Flow

1. Copy the API `requestId` from the error response.
2. Search for that ID in `logs/backend-debug.log`.
3. Check the `urgencyLevel`.
4. Fix client/request issues first for levels `2-4`.
5. Review account state, permissions, or policy settings for levels `5-6`.
6. Treat levels `7-9` as backend/operator investigation work.
