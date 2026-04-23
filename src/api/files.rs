use axum::{
    extract::{Extension, Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};

use crate::{
    api::contracts::FileUploadIntentRequest,
    auth,
    request_context::RequestContext,
    services::files as file_service,
    utils::envelope,
    AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/files/uploads", post(create_file_upload_intent))
        .route("/files/uploads/{file_id}/complete", post(complete_file_upload))
        .route("/me/files/{file_id}", get(get_own_file))
        .route("/me/files/{file_id}/download", get(get_own_file_download))
}

async fn create_file_upload_intent(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Json(request): Json<FileUploadIntentRequest>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| crate::error::AppError::validation("Idempotency-Key header is required"))?;
    let intent = file_service::create_file_upload_intent(&state, &auth_context, idempotency_key, request).await?;
    Ok((axum::http::StatusCode::CREATED, Json(envelope(&context.request_id, intent))))
}

async fn complete_file_upload(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(file_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let record = file_service::complete_file_upload(&state, &auth_context, file_id).await?;
    Ok(Json(envelope(&context.request_id, record)))
}

async fn get_own_file(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(file_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let record = file_service::get_own_file(&state, &auth_context, file_id).await?;
    Ok(Json(envelope(&context.request_id, record)))
}

async fn get_own_file_download(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    headers: HeaderMap,
    Path(file_id): Path<uuid::Uuid>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let auth_context = auth::require_auth(&state, &headers).await?;
    let download = file_service::get_own_file_download(&state, &auth_context, file_id).await?;
    Ok(Json(envelope(&context.request_id, download)))
}

#[derive(Debug, serde::Deserialize)]
pub struct SignedTransferQuery {
    pub expires: i64,
    pub signature: String,
}
