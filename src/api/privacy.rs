use axum::{
    extract::{Extension, Path, Query, State},
    http::HeaderMap,
    routing::{get, post, put},
    Json, Router,
};
use tower_cookies::{Cookie, Cookies};

use crate::{
    api::contracts::{CookiePreferencesUpdateRequest, PaginationQuery, PrivacyConsentCreateRequest, PrivacyRequestCreateRequest},
    auth,
    request_context::RequestContext,
    services::privacy as privacy_service,
    utils::{decode_offset_cursor, envelope, envelope_with_cursor},
    AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/legal/documents", get(list_legal_documents))
        .route("/me/privacy-consents", get(list_privacy_consents).post(create_privacy_consents))
        .route("/me/privacy-requests", get(list_privacy_requests).post(create_privacy_request))
        .route("/me/privacy-requests/{privacy_request_id}", get(get_privacy_request))
        .route("/privacy/cookie-preferences", get(get_cookie_preferences).put(set_cookie_preferences))
}

async fn list_legal_documents(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let documents = privacy_service::list_legal_documents(&state).await?;
    Ok(Json(envelope(&context.request_id, documents)))
}

async fn list_privacy_consents(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let consents = privacy_service::list_privacy_consents(&state, &auth_context).await?;
    Ok(Json(envelope(&context.request_id, consents)))
}

async fn create_privacy_consents(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<PrivacyConsentCreateRequest>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let consents = privacy_service::create_privacy_consents(&state, &auth_context, request).await?;
    Ok((axum::http::StatusCode::CREATED, Json(envelope(&context.request_id, consents))))
}

async fn list_privacy_requests(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query)?;
    let (requests, next_cursor) = privacy_service::list_privacy_requests(&state, &auth_context, offset, limit).await?;
    Ok(Json(envelope_with_cursor(&context.request_id, requests, next_cursor)))
}

async fn create_privacy_request(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<PrivacyRequestCreateRequest>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let privacy_request = privacy_service::create_privacy_request(&state, &auth_context, request).await?;
    Ok((axum::http::StatusCode::CREATED, Json(envelope(&context.request_id, privacy_request))))
}

async fn get_privacy_request(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(privacy_request_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let privacy_request = privacy_service::get_privacy_request(&state, &auth_context, privacy_request_id).await?;
    Ok(Json(envelope(&context.request_id, privacy_request)))
}

async fn get_cookie_preferences(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    cookies: Cookies,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::optional_auth(&state, &headers).await?;
    let anonymous_subject = ensure_cookie_subject(&cookies);
    let preferences = privacy_service::get_cookie_preferences(
        &state,
        auth_context.as_ref().map(|auth| auth.account_id),
        Some(crate::auth::sha256_hex(&anonymous_subject)),
    )
    .await?;
    Ok(Json(envelope(&context.request_id, preferences)))
}

async fn set_cookie_preferences(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(request): Json<CookiePreferencesUpdateRequest>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::optional_auth(&state, &headers).await?;
    let anonymous_subject = ensure_cookie_subject(&cookies);
    let preferences = privacy_service::set_cookie_preferences(
        &state,
        auth_context.as_ref().map(|auth| auth.account_id),
        Some(crate::auth::sha256_hex(&anonymous_subject)),
        request,
    )
    .await?;
    Ok(Json(envelope(&context.request_id, preferences)))
}

fn pagination(query: PaginationQuery) -> crate::error::AppResult<(i64, i64)> {
    let offset = decode_offset_cursor(query.cursor.as_deref())?;
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    Ok((offset, limit))
}

fn ensure_cookie_subject(cookies: &Cookies) -> String {
    if let Some(cookie) = cookies.get("cookie_subject") {
        cookie.value().to_string()
    } else {
        let token = crate::auth::generate_token(24);
        let mut cookie = Cookie::new("cookie_subject", token.clone());
        cookie.set_path("/");
        cookie.set_http_only(false);
        cookie.set_same_site(tower_cookies::cookie::SameSite::Lax);
        cookies.add(cookie);
        token
    }
}
