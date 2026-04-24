use axum::{
    extract::{Extension, Path, Query, State},
    http::HeaderMap,
    routing::{get, patch, post},
    Json, Router,
};

use crate::{
    api::contracts::{
        AdminSystemSettingUpdateRequest, AdminUserBulkActionRequest, AdminUserCreateRequest,
        AdminUserListQuery, AdminUserUpdateRequest, SearchPaginationQuery,
        SessionBulkRevokeRequest,
    },
    auth,
    request_context::RequestContext,
    services::admin as admin_service,
    utils::{decode_offset_cursor, envelope, envelope_with_cursor},
    AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/roles", get(list_roles))
        .route("/admin/overview", get(get_admin_overview))
        .route("/admin/audit-logs", get(list_audit_logs))
        .route("/admin/security/events", get(list_security_events))
        .route(
            "/admin/users",
            get(list_admin_users).post(create_admin_user),
        )
        .route(
            "/admin/users/{account_id}",
            get(get_admin_user).patch(update_admin_user),
        )
        .route(
            "/admin/users/{account_id}/sessions",
            get(list_admin_user_sessions),
        )
        .route(
            "/admin/users/{account_id}/sessions/revoke-all",
            post(revoke_admin_user_sessions),
        )
        .route(
            "/admin/users/{account_id}/security-events",
            get(list_admin_user_security_events),
        )
        .route(
            "/admin/users/{account_id}/audit-logs",
            get(list_admin_user_audit_logs),
        )
        .route(
            "/admin/users/{account_id}/emails/{email_id}/verify",
            post(admin_verify_user_email),
        )
        .route(
            "/admin/users/{account_id}/emails/{email_id}/unverify",
            post(admin_unverify_user_email),
        )
        .route("/admin/users/bulk-actions", post(bulk_admin_user_action))
        .route("/admin/settings", get(list_system_settings))
        .route(
            "/admin/settings/{setting_key}",
            patch(update_system_setting),
        )
}

async fn list_roles(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = admin_auth(&state, &headers).await?;
    let _ = auth_context;
    let roles = admin_service::list_roles(&state).await?;
    Ok(Json(envelope(&context.request_id, roles)))
}

async fn get_admin_overview(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let overview = admin_service::admin_overview(&state).await?;
    Ok(Json(envelope(&context.request_id, overview)))
}

async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<SearchPaginationQuery>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query.cursor.as_deref(), query.limit)?;
    let (logs, next_cursor) =
        admin_service::list_audit_logs(&state, query.query.as_deref(), offset, limit).await?;
    Ok(Json(envelope_with_cursor(
        &context.request_id,
        logs,
        next_cursor,
    )))
}

async fn list_security_events(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<SearchPaginationQuery>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query.cursor.as_deref(), query.limit)?;
    let (events, next_cursor) =
        admin_service::list_security_events(&state, query.query.as_deref(), offset, limit).await?;
    Ok(Json(envelope_with_cursor(
        &context.request_id,
        events,
        next_cursor,
    )))
}

async fn list_admin_users(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<AdminUserListQuery>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query.cursor.as_deref(), query.limit)?;
    let (users, next_cursor) = admin_service::list_admin_users(
        &state,
        query.query.as_deref(),
        query.status.as_deref(),
        query.role.as_deref(),
        offset,
        limit,
    )
    .await?;
    Ok(Json(envelope_with_cursor(
        &context.request_id,
        users,
        next_cursor,
    )))
}

async fn create_admin_user(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<AdminUserCreateRequest>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = admin_auth(&state, &headers).await?;
    let user = admin_service::create_admin_user(&state, &auth_context, &context, request).await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(envelope(&context.request_id, user)),
    ))
}

async fn get_admin_user(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(account_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let user = admin_service::get_admin_user(&state, account_id).await?;
    Ok(Json(envelope(&context.request_id, user)))
}

async fn update_admin_user(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(account_id): Path<uuid::Uuid>,
    Json(request): Json<AdminUserUpdateRequest>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = admin_auth(&state, &headers).await?;
    let user =
        admin_service::update_admin_user(&state, &auth_context, &context, account_id, request)
            .await?;
    Ok(Json(envelope(&context.request_id, user)))
}

async fn list_admin_user_sessions(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(account_id): Path<uuid::Uuid>,
    Query(query): Query<crate::api::contracts::PaginationQuery>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query.cursor.as_deref(), query.limit)?;
    let (sessions, next_cursor) =
        admin_service::list_admin_user_sessions(&state, account_id, offset, limit).await?;
    Ok(Json(envelope_with_cursor(
        &context.request_id,
        sessions,
        next_cursor,
    )))
}

async fn revoke_admin_user_sessions(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(account_id): Path<uuid::Uuid>,
    maybe_body: Option<Json<SessionBulkRevokeRequest>>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = admin_auth(&state, &headers).await?;
    let request = maybe_body.map(|Json(value)| value).unwrap_or_default();
    let acknowledgement = admin_service::revoke_admin_user_sessions(
        &state,
        &auth_context,
        &context,
        account_id,
        request,
    )
    .await?;
    Ok(Json(envelope(&context.request_id, acknowledgement)))
}

async fn list_admin_user_security_events(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(account_id): Path<uuid::Uuid>,
    Query(query): Query<crate::api::contracts::PaginationQuery>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query.cursor.as_deref(), query.limit)?;
    let (events, next_cursor) =
        admin_service::list_admin_user_security_events(&state, account_id, offset, limit).await?;
    Ok(Json(envelope_with_cursor(
        &context.request_id,
        events,
        next_cursor,
    )))
}

async fn list_admin_user_audit_logs(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(account_id): Path<uuid::Uuid>,
    Query(query): Query<crate::api::contracts::PaginationQuery>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query.cursor.as_deref(), query.limit)?;
    let (logs, next_cursor) =
        admin_service::list_admin_user_audit_logs(&state, account_id, offset, limit).await?;
    Ok(Json(envelope_with_cursor(
        &context.request_id,
        logs,
        next_cursor,
    )))
}

async fn admin_verify_user_email(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((account_id, email_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let email = admin_service::admin_verify_user_email(&state, account_id, email_id).await?;
    Ok(Json(envelope(&context.request_id, email)))
}

async fn admin_unverify_user_email(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path((account_id, email_id)): Path<(uuid::Uuid, uuid::Uuid)>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let email = admin_service::admin_unverify_user_email(&state, account_id, email_id).await?;
    Ok(Json(envelope(&context.request_id, email)))
}

async fn bulk_admin_user_action(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<AdminUserBulkActionRequest>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = admin_auth(&state, &headers).await?;
    let acknowledgement =
        admin_service::bulk_admin_user_action(&state, &auth_context, &context, request).await?;
    Ok(Json(envelope(&context.request_id, acknowledgement)))
}

async fn list_system_settings(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let _ = admin_auth(&state, &headers).await?;
    let settings = admin_service::list_system_settings(&state).await?;
    Ok(Json(envelope(&context.request_id, settings)))
}

async fn update_system_setting(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(setting_key): Path<String>,
    Json(request): Json<AdminSystemSettingUpdateRequest>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = admin_auth(&state, &headers).await?;
    let setting =
        admin_service::update_system_setting(&state, &auth_context, &setting_key, request).await?;
    Ok(Json(envelope(&context.request_id, setting)))
}

async fn admin_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> crate::error::AppResult<auth::AuthContext> {
    let auth_context = auth::require_auth(state, headers).await?;
    auth_context.require_admin()?;
    Ok(auth_context)
}

fn pagination(cursor: Option<&str>, limit: Option<i64>) -> crate::error::AppResult<(i64, i64)> {
    let offset = decode_offset_cursor(cursor)?;
    Ok((offset, limit.unwrap_or(20).clamp(1, 100)))
}
