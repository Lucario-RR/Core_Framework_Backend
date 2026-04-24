use std::{env, net::SocketAddr, path::PathBuf};

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub app_base_url: String,
    pub jwt_secret: String,
    pub cookie_secure: bool,
    pub public_admin_bootstrap_enabled: bool,
    pub upload_dir: PathBuf,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_seconds: i64,
    pub password_reset_ttl_seconds: i64,
    pub email_verification_ttl_seconds: i64,
    pub totp_issuer: String,
}

impl AppConfig {
    pub fn from_env() -> AppResult<Self> {
        let bind_addr = required("BIND_ADDR")?
            .parse::<SocketAddr>()
            .map_err(|error| AppError::internal(format!("failed to parse BIND_ADDR: {error}")))?;

        Ok(Self {
            database_url: required("DATABASE_URL")?,
            bind_addr,
            app_base_url: env_or("APP_BASE_URL", "http://localhost:11451"),
            jwt_secret: required("JWT_SECRET")?,
            cookie_secure: env_bool("COOKIE_SECURE", false),
            public_admin_bootstrap_enabled: env_bool("PUBLIC_ADMIN_BOOTSTRAP_ENABLED", false),
            upload_dir: PathBuf::from(env_or("UPLOAD_DIR", "storage")),
            access_token_ttl_seconds: env_i64("ACCESS_TOKEN_TTL_SECONDS", 900)?,
            refresh_token_ttl_seconds: env_i64("REFRESH_TOKEN_TTL_SECONDS", 60 * 60 * 24 * 30)?,
            password_reset_ttl_seconds: env_i64("PASSWORD_RESET_TTL_SECONDS", 60 * 60)?,
            email_verification_ttl_seconds: env_i64(
                "EMAIL_VERIFICATION_TTL_SECONDS",
                60 * 60 * 24,
            )?,
            totp_issuer: env_or("TOTP_ISSUER", "CoreFrameworkBackend"),
        })
    }
}

fn required(key: &str) -> AppResult<String> {
    env::var(key)
        .map_err(|_| AppError::internal(format!("missing required environment variable {key}")))
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn env_i64(key: &str, default: i64) -> AppResult<i64> {
    match env::var(key) {
        Ok(value) => value.parse::<i64>().map_err(|error| {
            AppError::internal(format!("failed to parse {key} as integer: {error}"))
        }),
        Err(_) => Ok(default),
    }
}
