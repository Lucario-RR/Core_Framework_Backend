pub mod admin;
pub mod auth_routes;
pub mod contracts;
pub mod files;
pub mod internal;
pub mod privacy;
pub mod users;

use axum::Json;

use crate::{api::contracts::Acknowledgement, utils::envelope};

pub async fn health() -> Json<crate::api::contracts::ApiEnvelope<Acknowledgement>> {
    Json(envelope(
        "health",
        Acknowledgement {
            status: "ok".to_string(),
            message: Some("service healthy".to_string()),
        },
    ))
}
