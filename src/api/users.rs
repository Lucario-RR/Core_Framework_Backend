use axum::{
    extract::{Extension, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, patch, post},
    Json, Router,
};

use crate::{
    api::contracts::{
        AccountDeactivateRequest, AvatarUpdateRequest, EmailAddressCreateRequest, EmailChangeRequestCreateRequest,
        PaginationQuery, PasskeyRegistrationOptionsRequest, PasskeyRegistrationVerifyRequest, PhoneNumberCreateRequest,
        ProfileUpdateRequest, SecurityReportCreateRequest, SessionBulkRevokeRequest, TotpEnableRequest,
        VerificationCodeRequest,
    },
    auth,
    request_context::RequestContext,
    services::user as user_service,
    utils::{decode_offset_cursor, envelope, envelope_with_cursor},
    AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/me", get(get_me).patch(update_me))
        .route("/me/avatar", post(set_avatar).delete(remove_avatar))
        .route("/me/account/deactivate", post(deactivate_own_account))
        .route("/me/sessions", get(list_own_sessions))
        .route("/me/sessions/revoke-all", post(revoke_all_own_sessions))
        .route("/me/sessions/{session_id}", delete(revoke_own_session))
        .route("/me/security", get(get_security_summary))
        .route("/me/security/events", get(list_own_security_events))
        .route("/me/security/reports", post(create_security_report))
        .route("/me/passkeys", get(list_passkeys))
        .route(
            "/me/passkeys/registration/options",
            post(create_passkey_registration_options),
        )
        .route(
            "/me/passkeys/registration/verify",
            post(verify_passkey_registration),
        )
        .route("/me/passkeys/{passkey_id}", delete(delete_passkey))
        .route("/me/mfa/totp/setup", post(create_totp_setup))
        .route("/me/mfa/totp/enable", post(enable_totp))
        .route("/me/mfa/totp/disable", post(disable_totp))
        .route("/me/mfa/recovery-codes/rotate", post(rotate_recovery_codes))
        .route("/me/emails", get(list_emails).post(create_email))
        .route("/me/emails/{email_id}", delete(delete_email))
        .route("/me/emails/{email_id}/verify", post(verify_email))
        .route("/me/emails/{email_id}/make-primary", post(make_email_primary))
        .route(
            "/me/emails/{email_id}/resend-verification",
            post(resend_email_verification),
        )
        .route("/me/email-change-requests", post(create_email_change_request))
        .route("/me/phones", get(list_phones).post(create_phone))
        .route("/me/phones/{phone_id}", delete(delete_phone))
        .route("/me/phones/{phone_id}/verify", post(verify_phone))
        .route("/me/phones/{phone_id}/make-primary", post(make_phone_primary))
}

async fn get_me(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let (profile, etag) = user_service::get_me(&state, &auth_context).await?;
    Ok(([(header::ETAG, etag)], Json(envelope(&context.request_id, profile))))
}

async fn update_me(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<ProfileUpdateRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let if_match = headers.get(header::IF_MATCH).and_then(|value| value.to_str().ok());
    let (profile, etag) = user_service::update_me(&state, &auth_context, if_match, request).await?;
    Ok(([(header::ETAG, etag)], Json(envelope(&context.request_id, profile))))
}

async fn set_avatar(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<AvatarUpdateRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let (profile, etag) = user_service::set_avatar(&state, &auth_context, request).await?;
    Ok(([(header::ETAG, etag)], Json(envelope(&context.request_id, profile))))
}

async fn remove_avatar(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let (profile, etag) = user_service::remove_avatar(&state, &auth_context).await?;
    Ok(([(header::ETAG, etag)], Json(envelope(&context.request_id, profile))))
}

async fn deactivate_own_account(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<AccountDeactivateRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let acknowledgement = user_service::deactivate_own_account(&state, &auth_context, &context, request).await?;
    Ok(Json(envelope(&context.request_id, acknowledgement)))
}

async fn list_own_sessions(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query)?;
    let (sessions, next_cursor) = user_service::list_own_sessions(&state, &auth_context, offset, limit).await?;
    Ok(Json(envelope_with_cursor(&context.request_id, sessions, next_cursor)))
}

async fn revoke_all_own_sessions(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    maybe_body: Option<Json<SessionBulkRevokeRequest>>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let request = maybe_body.map(|Json(value)| value).unwrap_or_default();
    let acknowledgement = user_service::revoke_all_own_sessions(&state, &auth_context, &context, request).await?;
    Ok(Json(envelope(&context.request_id, acknowledgement)))
}

async fn revoke_own_session(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(session_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    user_service::revoke_own_session(&state, &auth_context, session_id, &context).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_security_summary(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let summary = user_service::get_security_summary(&state, &auth_context).await?;
    Ok(Json(envelope(&context.request_id, summary)))
}

async fn list_own_security_events(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Query(query): Query<PaginationQuery>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let (offset, limit) = pagination(query)?;
    let (events, next_cursor) = user_service::list_own_security_events(&state, &auth_context, offset, limit).await?;
    Ok(Json(envelope_with_cursor(&context.request_id, events, next_cursor)))
}

async fn create_security_report(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<SecurityReportCreateRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let acknowledgement = user_service::create_security_report(&state, &auth_context, &context, request).await?;
    Ok((StatusCode::CREATED, Json(envelope(&context.request_id, acknowledgement))))
}

async fn list_passkeys(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let passkeys = user_service::list_passkeys(&state, &auth_context).await?;
    Ok(Json(envelope(&context.request_id, passkeys)))
}

async fn create_passkey_registration_options(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    maybe_body: Option<Json<PasskeyRegistrationOptionsRequest>>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let request = maybe_body
        .map(|Json(value)| value)
        .unwrap_or(PasskeyRegistrationOptionsRequest { display_name: None });
    let options = user_service::create_passkey_registration_options(&state, &auth_context, request).await?;
    Ok(Json(envelope(&context.request_id, options)))
}

async fn verify_passkey_registration(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<PasskeyRegistrationVerifyRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let passkey = user_service::verify_passkey_registration(&state, &auth_context, request).await?;
    Ok((StatusCode::CREATED, Json(envelope(&context.request_id, passkey))))
}

async fn delete_passkey(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(passkey_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    user_service::delete_passkey(&state, &auth_context, passkey_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_totp_setup(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let setup = user_service::create_totp_setup(&state, &auth_context).await?;
    Ok(Json(envelope(&context.request_id, setup)))
}

async fn enable_totp(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<TotpEnableRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let summary = user_service::enable_totp(&state, &auth_context, request).await?;
    Ok(Json(envelope(&context.request_id, summary)))
}

async fn disable_totp(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<VerificationCodeRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let summary = user_service::disable_totp(&state, &auth_context, request).await?;
    Ok(Json(envelope(&context.request_id, summary)))
}

async fn rotate_recovery_codes(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let codes = user_service::rotate_recovery_codes(&state, &auth_context).await?;
    Ok(Json(envelope(&context.request_id, codes)))
}

async fn list_emails(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let emails = user_service::list_emails(&state, &auth_context).await?;
    Ok(Json(envelope(&context.request_id, emails)))
}

async fn create_email(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<EmailAddressCreateRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let email = user_service::create_email(&state, &auth_context, &context, request).await?;
    Ok((StatusCode::CREATED, Json(envelope(&context.request_id, email))))
}

async fn delete_email(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(email_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    user_service::delete_email(&state, &auth_context, email_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_email(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(email_id): Path<uuid::Uuid>,
    Json(request): Json<VerificationCodeRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let email = user_service::verify_email(&state, &auth_context, email_id, request).await?;
    Ok(Json(envelope(&context.request_id, email)))
}

async fn make_email_primary(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(email_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let email = user_service::make_email_primary(&state, &auth_context, email_id).await?;
    Ok(Json(envelope(&context.request_id, email)))
}

async fn resend_email_verification(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(email_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let acknowledgement =
        user_service::resend_email_verification(&state, &auth_context, &context, email_id).await?;
    Ok((StatusCode::ACCEPTED, Json(envelope(&context.request_id, acknowledgement))))
}

async fn create_email_change_request(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<EmailChangeRequestCreateRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let acknowledgement = user_service::create_email_change_request(&state, &auth_context, &context, request).await?;
    Ok((StatusCode::CREATED, Json(envelope(&context.request_id, acknowledgement))))
}

async fn list_phones(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let phones = user_service::list_phones(&state, &auth_context).await?;
    Ok(Json(envelope(&context.request_id, phones)))
}

async fn create_phone(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<PhoneNumberCreateRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let phone = user_service::create_phone(&state, &auth_context, &context, request).await?;
    Ok((StatusCode::CREATED, Json(envelope(&context.request_id, phone))))
}

async fn delete_phone(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(phone_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    user_service::delete_phone(&state, &auth_context, phone_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_phone(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(phone_id): Path<uuid::Uuid>,
    Json(request): Json<VerificationCodeRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let phone = user_service::verify_phone(&state, &auth_context, phone_id, request).await?;
    Ok(Json(envelope(&context.request_id, phone)))
}

async fn make_phone_primary(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(phone_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let phone = user_service::make_phone_primary(&state, &auth_context, phone_id).await?;
    Ok(Json(envelope(&context.request_id, phone)))
}

fn pagination(query: PaginationQuery) -> crate::error::AppResult<(i64, i64)> {
    let offset = decode_offset_cursor(query.cursor.as_deref())?;
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    Ok((offset, limit))
}
