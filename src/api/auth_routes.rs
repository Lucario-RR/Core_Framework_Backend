use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use tower_cookies::Cookies;

use crate::{
    api::contracts::{
        Acknowledgement, EmailVerificationConfirmRequest, EmailVerificationResendRequest, LoginRequest, MfaVerifyRequest,
        PasskeyAuthenticationOptionsRequest, PasskeyAuthenticationVerifyRequest, PasswordChangeRequest,
        PasswordForgotRequest, PasswordResetRequest, RegisterRequest,
    },
    auth,
    request_context::RequestContext,
    services::auth::{self as auth_service, LoginOutcome},
    utils::envelope,
    AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/register-admin", post(register_admin))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/password/change", post(change_password))
        .route("/auth/password/forgot", post(start_password_reset))
        .route("/auth/password/reset", post(complete_password_reset))
        .route("/auth/email/verify", post(verify_email_challenge))
        .route("/auth/email/resend", post(resend_primary_email_verification))
        .route("/auth/mfa/verify", post(verify_mfa_challenge))
        .route(
            "/auth/passkeys/authentication/options",
            post(create_passkey_authentication_options),
        )
        .route(
            "/auth/passkeys/authentication/verify",
            post(verify_passkey_authentication),
        )
}

async fn register(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    cookies: Cookies,
    Json(request): Json<RegisterRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let session = auth_service::register(&state, &cookies, &context, request).await?;
    Ok((StatusCode::CREATED, Json(envelope(&context.request_id, session))))
}

async fn register_admin(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    cookies: Cookies,
    Json(request): Json<RegisterRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let session = auth_service::register_admin_bootstrap(&state, &cookies, &context, request).await?;
    Ok((StatusCode::CREATED, Json(envelope(&context.request_id, session))))
}

async fn login(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    cookies: Cookies,
    Json(request): Json<LoginRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    match auth_service::login(&state, &cookies, &context, request).await? {
        LoginOutcome::Session(session) => Ok((StatusCode::OK, Json(envelope(&context.request_id, session))).into_response()),
        LoginOutcome::Challenge(challenge) => {
            Ok((StatusCode::ACCEPTED, Json(envelope(&context.request_id, challenge))).into_response())
        }
    }
}

async fn refresh(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    cookies: Cookies,
) -> crate::error::AppResult<impl IntoResponse> {
    let session = auth_service::refresh_session(&state, &cookies, &headers, &context).await?;
    Ok((StatusCode::OK, Json(envelope(&context.request_id, session))))
}

async fn logout(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    cookies: Cookies,
) -> crate::error::AppResult<impl IntoResponse> {
    auth_service::logout(&state, &headers, &cookies, &context).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn change_password(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: axum::http::HeaderMap,
    Json(request): Json<PasswordChangeRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let acknowledgement = auth_service::change_password(&state, &auth_context, &context, request).await?;
    Ok(Json(envelope(&context.request_id, acknowledgement)))
}

async fn start_password_reset(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<PasswordForgotRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let acknowledgement = auth_service::start_password_reset(&state, &context, request).await?;
    Ok((StatusCode::ACCEPTED, Json(envelope(&context.request_id, acknowledgement))))
}

async fn complete_password_reset(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<PasswordResetRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    auth_service::complete_password_reset(&state, &context, request).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_email_challenge(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<EmailVerificationConfirmRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let acknowledgement = auth_service::verify_email_challenge(&state, &context, request).await?;
    Ok(Json(envelope(&context.request_id, acknowledgement)))
}

async fn resend_primary_email_verification(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Json(request): Json<EmailVerificationResendRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let acknowledgement = auth_service::resend_primary_email_verification(&state, &context, request).await?;
    Ok((StatusCode::ACCEPTED, Json(envelope(&context.request_id, acknowledgement))))
}

async fn verify_mfa_challenge(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    cookies: Cookies,
    Json(request): Json<MfaVerifyRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let session = auth_service::verify_mfa_challenge(&state, &cookies, &context, request).await?;
    Ok(Json(envelope(&context.request_id, session)))
}

async fn create_passkey_authentication_options(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    maybe_body: Option<Json<PasskeyAuthenticationOptionsRequest>>,
) -> crate::error::AppResult<impl IntoResponse> {
    let request = maybe_body
        .map(|Json(value)| value)
        .unwrap_or(PasskeyAuthenticationOptionsRequest { email: None });
    let response = auth_service::create_passkey_authentication_options(&state, request).await?;
    Ok(Json(envelope(&context.request_id, response)))
}

async fn verify_passkey_authentication(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    cookies: Cookies,
    Json(request): Json<PasskeyAuthenticationVerifyRequest>,
) -> crate::error::AppResult<impl IntoResponse> {
    let session = auth_service::verify_passkey_authentication(&state, &cookies, &context, request).await?;
    Ok(Json(envelope(&context.request_id, session)))
}

#[allow(dead_code)]
fn _ack(_value: Acknowledgement) {}
