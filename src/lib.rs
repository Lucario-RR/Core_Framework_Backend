pub mod api;
pub mod auth;
pub mod config;
pub mod error;
pub mod request_context;
pub mod services;
pub mod utils;

use std::sync::Arc;

use axum::{middleware, routing::get, Router};
use sqlx::{migrate::Migrator, PgPool};
use tower_cookies::CookieManagerLayer;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    api::{admin, auth_routes, files, internal, privacy, users},
    config::AppConfig,
    request_context::inject_request_context,
};

pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<AppConfig>,
}

impl AppState {
    pub fn new(pool: PgPool, config: AppConfig) -> Self {
        Self {
            pool,
            config: Arc::new(config),
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let api_router = Router::new()
        .merge(auth_routes::routes())
        .merge(users::routes())
        .merge(files::routes())
        .merge(privacy::routes())
        .merge(admin::routes());

    Router::new()
        .route("/health", get(api::health))
        .nest("/api/v1", api_router)
        .merge(internal::routes())
        .layer(CorsLayer::permissive())
        .layer(CookieManagerLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(inject_request_context))
        .with_state(state)
}
