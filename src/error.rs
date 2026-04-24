use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct AppError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub urgency_level: u8,
    pub details: Option<Value>,
    pub request_id: Option<String>,
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    pub fn validation(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "VALIDATION_ERROR",
            message: message.into(),
            urgency_level: 3,
            details: None,
            request_id: None,
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "UNAUTHORIZED",
            message: message.into(),
            urgency_level: 4,
            details: None,
            request_id: None,
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "FORBIDDEN",
            message: message.into(),
            urgency_level: 5,
            details: None,
            request_id: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NOT_FOUND",
            message: message.into(),
            urgency_level: 2,
            details: None,
            request_id: None,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "CONFLICT",
            message: message.into(),
            urgency_level: 5,
            details: None,
            request_id: None,
        }
    }

    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "RATE_LIMITED",
            message: message.into(),
            urgency_level: 6,
            details: None,
            request_id: None,
        }
    }

    pub fn precondition_failed(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PRECONDITION_FAILED,
            code: "PRECONDITION_FAILED",
            message: message.into(),
            urgency_level: 4,
            details: None,
            request_id: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "INTERNAL_ERROR",
            message: message.into(),
            urgency_level: 8,
            details: None,
            request_id: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    pub fn with_urgency_level(mut self, urgency_level: u8) -> Self {
        self.urgency_level = urgency_level.clamp(1, 9);
        self
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal(format!("database error: {error}"))
    }
}

impl From<sqlx::migrate::MigrateError> for AppError {
    fn from(error: sqlx::migrate::MigrateError) -> Self {
        Self::internal(format!("database migration error: {error}")).with_urgency_level(9)
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::internal(format!("io error: {error}"))
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        Self::unauthorized(format!("token error: {error}"))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorObject {
    code: &'static str,
    message: String,
    urgency_level: u8,
    details: Option<Value>,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorObject,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status;
        let code = self.code;
        let message = self.message;
        let urgency_level = self.urgency_level.clamp(1, 9);
        let details = self.details;
        let request_id = self
            .request_id
            .unwrap_or_else(|| format!("req_{}", uuid::Uuid::new_v4().simple()));
        let details_for_log = details
            .as_ref()
            .map(Value::to_string)
            .unwrap_or_else(|| "null".to_string());

        match urgency_level {
            1..=3 => tracing::info!(
                status = status.as_u16(),
                code,
                urgency_level,
                request_id,
                details = %details_for_log,
                message = %message,
                "request completed with low-urgency error"
            ),
            4..=6 => tracing::warn!(
                status = status.as_u16(),
                code,
                urgency_level,
                request_id,
                details = %details_for_log,
                message = %message,
                "request completed with medium-urgency error"
            ),
            _ => tracing::error!(
                status = status.as_u16(),
                code,
                urgency_level,
                request_id,
                details = %details_for_log,
                message = %message,
                "request completed with high-urgency error"
            ),
        };

        (
            status,
            Json(ErrorEnvelope {
                error: ErrorObject {
                    code,
                    message,
                    urgency_level,
                    details,
                    request_id,
                },
            }),
        )
            .into_response()
    }
}
