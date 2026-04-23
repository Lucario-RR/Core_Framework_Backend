use std::env;

use tokio::fs;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use core_framework_backend::{build_router, config::AppConfig, error::AppError, AppState, MIGRATOR};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenvy::dotenv().ok();
    let _log_guard = init_tracing()?;

    let config = AppConfig::from_env()?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    MIGRATOR.run(&pool).await?;
    fs::create_dir_all(&config.upload_dir).await?;

    let bind_addr = config.bind_addr;
    let state = AppState::new(pool, config);
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!("listening on {bind_addr}");
    axum::serve(listener, app).await.map_err(|error| AppError::internal(format!("server error: {error}")))
}

fn init_tracing() -> Result<WorkerGuard, AppError> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,core_framework_backend=debug"));
    let log_dir = env::var("LOG_DIR").unwrap_or_else(|_| "logs".to_string());
    std::fs::create_dir_all(&log_dir)
        .map_err(|error| AppError::internal(format!("failed to create log directory {log_dir}: {error}")))?;

    let file_appender = tracing_appender::rolling::never(&log_dir, "backend-debug.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let stdout_layer = tracing_subscriber::fmt::layer().with_target(false);
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}
