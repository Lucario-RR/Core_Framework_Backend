use std::path::PathBuf;

use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
};
use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::Row;
use tokio::fs;
use uuid::Uuid;

use crate::{
    api::contracts::{FileDownload, FileRecord, FileUploadIntent, FileUploadIntentRequest},
    auth::{self, AuthContext},
    error::{AppError, AppResult},
    services::shared,
    AppState,
};

pub async fn create_file_upload_intent(
    state: &AppState,
    auth_context: &AuthContext,
    idempotency_key: &str,
    request: FileUploadIntentRequest,
) -> AppResult<FileUploadIntent> {
    if request.size <= 0 || request.size > 10 * 1024 * 1024 {
        return Err(AppError::validation(
            "size must be between 1 byte and 10 MB",
        ));
    }

    let filename = request.filename.clone();
    let content_type = request.content_type.clone();
    let purpose = request.purpose.clone();
    let checksum_sha256 = request.checksum_sha256.clone();
    let metadata_content_type = content_type.clone();
    let metadata_purpose = purpose.clone();

    let idem_hash = auth::sha256_hex(idempotency_key);
    let cached = sqlx::query_scalar::<_, serde_json::Value>(
        r#"
        select response_json
        from ops.idempotency_key
        where scope_code = 'file.upload.intent'
          and account_id = $1
          and key_hash = $2
        limit 1
        "#,
    )
    .bind(auth_context.account_id)
    .bind(&idem_hash)
    .fetch_optional(&state.pool)
    .await?;

    if let Some(payload) = cached {
        let parsed = serde_json::from_value::<FileUploadIntent>(payload).map_err(|error| {
            AppError::internal(format!("failed to decode idempotent file intent: {error}"))
        })?;
        return Ok(parsed);
    }

    let file_id = Uuid::new_v4();
    let storage_id = Uuid::new_v4();
    let object_key = format!("{}/{}", auth_context.account_id, file_id);

    sqlx::query(
        r#"
        insert into file.storage_object (
            id, storage_provider, bucket_name, object_key, checksum_sha256, size_bytes, metadata_json, created_at
        )
        values ($1, 'local', 'private', $2, $3, $4, $5, now())
        "#,
    )
    .bind(storage_id)
    .bind(&object_key)
    .bind(checksum_sha256)
    .bind(request.size)
    .bind(json!({"contentType": metadata_content_type, "purpose": metadata_purpose}))
    .execute(&state.pool)
    .await?;

    sqlx::query(
        r#"
        insert into file.file_asset (
            id, storage_object_id, owner_account_id, original_filename, content_type, size_bytes,
            purpose_code, status, metadata_stripped, classification_code, created_at, updated_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, 'upload_pending', false, 'PRIVATE', now(), now())
        "#,
    )
    .bind(file_id)
    .bind(storage_id)
    .bind(auth_context.account_id)
    .bind(filename)
    .bind(content_type.clone())
    .bind(request.size)
    .bind(purpose)
    .execute(&state.pool)
    .await?;

    let expires_at = Utc::now() + Duration::minutes(15);
    let signature = auth::sign_ephemeral_url(
        &state.config.jwt_secret,
        "upload",
        file_id,
        expires_at.timestamp(),
    );
    let upload_url = format!(
        "{}/internal/uploads/{}?expires={}&signature={}",
        state.config.app_base_url,
        file_id,
        expires_at.timestamp(),
        signature
    );
    let response = FileUploadIntent {
        file_id,
        upload_url,
        expires_at,
        required_headers: Some(
            [("content-type".to_string(), content_type)]
                .into_iter()
                .collect(),
        ),
    };

    sqlx::query(
        r#"
        insert into ops.idempotency_key (
            id, scope_code, account_id, key_hash, response_json, created_at, expires_at
        )
        values ($1, 'file.upload.intent', $2, $3, $4, now(), now() + interval '1 day')
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(auth_context.account_id)
    .bind(idem_hash)
    .bind(
        serde_json::to_value(&response)
            .map_err(|error| AppError::internal(format!("failed to encode response: {error}")))?,
    )
    .execute(&state.pool)
    .await?;

    Ok(response)
}

pub async fn complete_file_upload(
    state: &AppState,
    auth_context: &AuthContext,
    file_id: Uuid,
) -> AppResult<FileRecord> {
    let row = sqlx::query(
        r#"
        select fs.object_key, fs.size_bytes as expected_size
        from file.file_asset fa
        join file.storage_object fs on fs.id = fa.storage_object_id
        where fa.id = $1
          and fa.owner_account_id = $2
          and fa.deleted_at is null
        limit 1
        "#,
    )
    .bind(file_id)
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("file not found"))?;

    let object_key: String = row.try_get("object_key")?;
    let expected_size: i64 = row.try_get("expected_size")?;
    let path = build_storage_path(&state.config.upload_dir, &object_key);

    let metadata = fs::metadata(&path)
        .await
        .map_err(|_| AppError::conflict("upload has not been received yet"))?;
    if metadata.len() as i64 != expected_size {
        return Err(AppError::conflict(
            "uploaded file size does not match the intent",
        ));
    }

    sqlx::query(
        r#"
        update file.file_asset
        set status = 'ready',
            metadata_stripped = case when content_type like 'image/%' then true else metadata_stripped end,
            updated_at = now()
        where id = $1 and owner_account_id = $2
        "#,
    )
    .bind(file_id)
    .bind(auth_context.account_id)
    .execute(&state.pool)
    .await?;

    shared::load_file_record(&state.pool, file_id, Some(auth_context.account_id)).await
}

pub async fn get_own_file(
    state: &AppState,
    auth_context: &AuthContext,
    file_id: Uuid,
) -> AppResult<FileRecord> {
    shared::load_file_record(&state.pool, file_id, Some(auth_context.account_id)).await
}

pub async fn get_own_file_download(
    state: &AppState,
    auth_context: &AuthContext,
    file_id: Uuid,
) -> AppResult<FileDownload> {
    shared::load_file_record(&state.pool, file_id, Some(auth_context.account_id)).await?;

    let expires_at = Utc::now() + Duration::minutes(10);
    let signature = auth::sign_ephemeral_url(
        &state.config.jwt_secret,
        "download",
        file_id,
        expires_at.timestamp(),
    );

    Ok(FileDownload {
        url: format!(
            "{}/internal/files/{}?expires={}&signature={}",
            state.config.app_base_url,
            file_id,
            expires_at.timestamp(),
            signature
        ),
        expires_at,
    })
}

pub async fn accept_internal_upload(
    state: &AppState,
    file_id: Uuid,
    expires: i64,
    signature: &str,
    content_type: Option<&str>,
    body: Bytes,
) -> AppResult<StatusCode> {
    if !auth::verify_ephemeral_url(
        &state.config.jwt_secret,
        "upload",
        file_id,
        expires,
        signature,
    ) {
        return Err(AppError::unauthorized(
            "upload signature is invalid or expired",
        ));
    }

    let row = sqlx::query(
        r#"
        select
            fs.object_key,
            fa.content_type,
            fa.size_bytes
        from file.file_asset fa
        join file.storage_object fs on fs.id = fa.storage_object_id
        where fa.id = $1
          and fa.deleted_at is null
        limit 1
        "#,
    )
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("file upload intent not found"))?;

    let expected_content_type: String = row.try_get("content_type")?;
    let expected_size: i64 = row.try_get("size_bytes")?;
    let object_key: String = row.try_get("object_key")?;

    if body.len() as i64 != expected_size {
        return Err(AppError::validation(
            "uploaded body size does not match the intent",
        ));
    }
    if let Some(content_type) = content_type {
        if content_type != expected_content_type {
            return Err(AppError::validation(
                "content type does not match the upload intent",
            ));
        }
    }

    let path = build_storage_path(&state.config.upload_dir, &object_key);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    fs::write(path, &body).await?;

    sqlx::query(
        "update file.file_asset set status = 'scan_pending', updated_at = now() where id = $1",
    )
    .bind(file_id)
    .execute(&state.pool)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn serve_internal_download(
    state: &AppState,
    file_id: Uuid,
    expires: i64,
    signature: &str,
) -> AppResult<impl IntoResponse> {
    if !auth::verify_ephemeral_url(
        &state.config.jwt_secret,
        "download",
        file_id,
        expires,
        signature,
    ) {
        return Err(AppError::unauthorized(
            "download signature is invalid or expired",
        ));
    }

    let row = sqlx::query(
        r#"
        select
            fs.object_key,
            fa.content_type,
            fa.original_filename
        from file.file_asset fa
        join file.storage_object fs on fs.id = fa.storage_object_id
        where fa.id = $1
          and fa.status = 'ready'
          and fa.deleted_at is null
        limit 1
        "#,
    )
    .bind(file_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("file not found"))?;

    let object_key: String = row.try_get("object_key")?;
    let content_type: String = row.try_get("content_type")?;
    let filename: String = row.try_get("original_filename")?;
    let path = build_storage_path(&state.config.upload_dir, &object_key);
    let bytes = fs::read(path).await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .map_err(|error| AppError::internal(format!("invalid content type header: {error}")))?,
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).map_err(
            |error| AppError::internal(format!("invalid content disposition header: {error}")),
        )?,
    );

    Ok((headers, bytes))
}

fn build_storage_path(root: &PathBuf, object_key: &str) -> PathBuf {
    let mut path = root.clone();
    for segment in object_key.split('/') {
        path.push(segment);
    }
    path
}
