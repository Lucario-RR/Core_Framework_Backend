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

## Notes

- File uploads start at `/api/v1/files/uploads`, then use the returned signed local upload URL under `/internal/uploads/...`.
- Private downloads start at `/api/v1/me/files/{fileId}/download`, which returns a short-lived signed local download URL.
- Bootstrap admin registration is controlled by both `PUBLIC_ADMIN_BOOTSTRAP_ENABLED` and the seeded system setting `registration.bootstrap_admin_enabled`.
- Local debug logs are written to `logs/backend-debug.log` by default. Set `LOG_DIR` to move them somewhere else.
