use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, put},
    Router,
};

use crate::{services::files as file_service, AppState};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/internal/uploads/{file_id}", put(upload_file))
        .route("/internal/files/{file_id}", get(download_file))
}

#[derive(Debug, serde::Deserialize)]
struct SignedTransferQuery {
    expires: i64,
    signature: String,
}

async fn upload_file(
    State(state): State<AppState>,
    Path(file_id): Path<uuid::Uuid>,
    Query(query): Query<SignedTransferQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    let content_type = headers
        .get("content-type")
        .and_then(|value| value.to_str().ok());
    let status = file_service::accept_internal_upload(
        &state,
        file_id,
        query.expires,
        &query.signature,
        content_type,
        body,
    )
    .await?;
    Ok(status)
}

async fn download_file(
    State(state): State<AppState>,
    Path(file_id): Path<uuid::Uuid>,
    Query(query): Query<SignedTransferQuery>,
) -> crate::error::AppResult<impl axum::response::IntoResponse> {
    file_service::serve_internal_download(&state, file_id, query.expires, &query.signature).await
}
