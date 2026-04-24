use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;

use crate::{
    api::contracts::{ApiEnvelope, ResponseMeta},
    error::{AppError, AppResult},
};

pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

pub fn envelope<T>(request_id: &str, data: T) -> ApiEnvelope<T>
where
    T: Serialize,
{
    ApiEnvelope {
        data,
        meta: ResponseMeta {
            request_id: request_id.to_string(),
            next_cursor: None,
        },
    }
}

pub fn envelope_with_cursor<T>(
    request_id: &str,
    data: T,
    next_cursor: Option<String>,
) -> ApiEnvelope<T>
where
    T: Serialize,
{
    ApiEnvelope {
        data,
        meta: ResponseMeta {
            request_id: request_id.to_string(),
            next_cursor,
        },
    }
}

pub fn encode_offset_cursor(offset: i64) -> String {
    URL_SAFE_NO_PAD.encode(format!("offset:{offset}").as_bytes())
}

pub fn decode_offset_cursor(cursor: Option<&str>) -> AppResult<i64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };

    let decoded = URL_SAFE_NO_PAD
        .decode(cursor.as_bytes())
        .map_err(|_| AppError::validation("cursor is invalid"))?;
    let decoded =
        String::from_utf8(decoded).map_err(|_| AppError::validation("cursor is invalid"))?;

    let Some(value) = decoded.strip_prefix("offset:") else {
        return Err(AppError::validation("cursor is invalid"));
    };

    value
        .parse::<i64>()
        .map_err(|_| AppError::validation("cursor is invalid"))
}

pub fn opt_string_is_blank(value: Option<&str>) -> bool {
    matches!(value, Some(v) if v.trim().is_empty())
}

pub fn validation_details(field: &str, message: &str) -> serde_json::Value {
    json!({
        "field": field,
        "message": message,
    })
}

pub fn sanitize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}
