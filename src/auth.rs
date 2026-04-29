use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use qrcode::{render::svg, QrCode};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::OffsetDateTime;
use tower_cookies::{
    cookie::{Cookie, SameSite},
    Cookies,
};
use uuid::Uuid;

use crate::{
    config::AppConfig,
    error::{AppError, AppResult},
    AppState,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct PasswordRecord {
    pub password_hash: String,
    pub salt_value: Vec<u8>,
    pub hash_parameters_json: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub sid: Uuid,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub account_id: Uuid,
    pub session_id: Uuid,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
}

impl AuthContext {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|candidate| candidate == role)
    }

    pub fn require_admin(&self) -> AppResult<()> {
        if self.has_role("admin") {
            Ok(())
        } else {
            Err(AppError::forbidden("administrator access is required"))
        }
    }
}

pub fn hash_password(password: &str) -> AppResult<PasswordRecord> {
    let mut salt_value = vec![0_u8; 16];
    OsRng.fill_bytes(&mut salt_value);
    let salt = SaltString::encode_b64(&salt_value)
        .map_err(|error| AppError::internal(format!("failed to encode salt: {error}")))?;
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|error| AppError::internal(format!("failed to build argon2 params: {error}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| AppError::internal(format!("failed to hash password: {error}")))?
        .to_string();

    Ok(PasswordRecord {
        password_hash,
        salt_value,
        hash_parameters_json: json!({
            "memory_kib": 19_456,
            "iterations": 2,
            "parallelism": 1,
            "version": "0x13"
        }),
    })
}

pub fn verify_password(password: &str, password_hash: &str) -> AppResult<bool> {
    let parsed = PasswordHash::new(password_hash)
        .map_err(|error| AppError::internal(format!("failed to parse password hash: {error}")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub fn generate_token(byte_length: usize) -> String {
    let mut bytes = vec![0_u8; byte_length];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn generate_numeric_code(length: usize) -> String {
    let mut rng = OsRng;
    (0..length)
        .map(|_| char::from(b'0' + (rng.gen_range(0..10) as u8)))
        .collect()
}

pub fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn create_access_token(
    config: &AppConfig,
    account_id: Uuid,
    session_id: Uuid,
    roles: Vec<String>,
    scopes: Vec<String>,
) -> AppResult<(String, i64)> {
    let issued_at = Utc::now();
    let expires_in_seconds = config.access_token_ttl_seconds;
    let expires_at = issued_at + Duration::seconds(expires_in_seconds);
    let claims = AccessTokenClaims {
        sub: account_id,
        sid: session_id,
        roles,
        scopes,
        exp: expires_at.timestamp() as usize,
        iat: issued_at.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(AppError::from)?;

    Ok((token, expires_in_seconds))
}

pub fn decode_access_token(config: &AppConfig, token: &str) -> AppResult<AccessTokenClaims> {
    let validation = Validation::default();
    let decoded = decode::<AccessTokenClaims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )?;
    Ok(decoded.claims)
}

pub fn set_auth_cookies(
    cookies: &Cookies,
    config: &AppConfig,
    refresh_token: &str,
    csrf_token: &str,
) {
    let refresh_expiry =
        OffsetDateTime::now_utc() + time::Duration::seconds(config.refresh_token_ttl_seconds);

    let mut refresh_cookie = Cookie::new("refresh_token", refresh_token.to_string());
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(config.cookie_secure);
    refresh_cookie.set_path("/api/v1");
    refresh_cookie.set_same_site(SameSite::Lax);
    refresh_cookie.set_expires(refresh_expiry);
    cookies.add(refresh_cookie);

    let mut old_csrf_cookie = Cookie::new("csrf_token", String::new());
    old_csrf_cookie.set_path("/api/v1");
    old_csrf_cookie.make_removal();
    cookies.add(old_csrf_cookie);

    let mut csrf_cookie = Cookie::new("csrf_token", csrf_token.to_string());
    csrf_cookie.set_http_only(false);
    csrf_cookie.set_secure(config.cookie_secure);
    csrf_cookie.set_path("/");
    csrf_cookie.set_same_site(SameSite::Lax);
    csrf_cookie.set_expires(refresh_expiry);
    cookies.add(csrf_cookie);
}

pub fn clear_auth_cookies(cookies: &Cookies) {
    let mut refresh_cookie = Cookie::new("refresh_token", String::new());
    refresh_cookie.set_path("/api/v1");
    refresh_cookie.make_removal();
    cookies.add(refresh_cookie);

    for path in ["/", "/api/v1"] {
        let mut csrf_cookie = Cookie::new("csrf_token", String::new());
        csrf_cookie.set_path(path);
        csrf_cookie.make_removal();
        cookies.add(csrf_cookie);
    }
}

pub async fn require_auth(state: &AppState, headers: &HeaderMap) -> AppResult<AuthContext> {
    let token = extract_bearer_token(headers)?;
    let claims = decode_access_token(&state.config, &token)?;

    let row = sqlx::query(
        r#"
        select id, account_id
        from auth.session
        where id = $1
          and account_id = $2
          and revoked_at is null
          and absolute_expires_at > now()
        "#,
    )
    .bind(claims.sid)
    .bind(claims.sub)
    .fetch_optional(&state.pool)
    .await?;

    if row.is_none() {
        return Err(AppError::unauthorized("session is no longer valid"));
    }

    Ok(AuthContext {
        account_id: claims.sub,
        session_id: claims.sid,
        roles: claims.roles,
        scopes: claims.scopes,
    })
}

pub async fn optional_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> AppResult<Option<AuthContext>> {
    if headers.get(http::header::AUTHORIZATION).is_none() {
        return Ok(None);
    }

    require_auth(state, headers).await.map(Some)
}

pub fn extract_bearer_token(headers: &HeaderMap) -> AppResult<String> {
    let Some(header_value) = headers.get(http::header::AUTHORIZATION) else {
        return Err(AppError::unauthorized("bearer token is required"));
    };

    let value = header_value
        .to_str()
        .map_err(|_| AppError::unauthorized("authorization header is invalid"))?;

    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err(AppError::unauthorized(
            "authorization header must use Bearer",
        ));
    };

    Ok(token.trim().to_string())
}

pub fn generate_totp_secret() -> Vec<u8> {
    let mut secret = vec![0_u8; 20];
    OsRng.fill_bytes(&mut secret);
    secret
}

pub fn encode_totp_secret(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

pub fn build_otpauth_uri(issuer: &str, account_label: &str, secret_base32: &str) -> String {
    let issuer_encoded = urlencoding::encode(issuer);
    let label_encoded = urlencoding::encode(account_label);
    format!(
        "otpauth://totp/{issuer_encoded}:{label_encoded}?secret={secret_base32}&issuer={issuer_encoded}"
    )
}

pub fn build_qr_code_svg_data_url(content: &str) -> AppResult<String> {
    let code = QrCode::new(content.as_bytes())
        .map_err(|error| AppError::internal(format!("failed to build qr code: {error}")))?;
    let svg_image = code.render::<svg::Color>().min_dimensions(256, 256).build();
    let encoded = STANDARD.encode(svg_image.as_bytes());
    Ok(format!("data:image/svg+xml;base64,{encoded}"))
}

pub fn verify_totp_code(secret: &[u8], code: &str, digits: u32, period_seconds: i64) -> bool {
    let now = Utc::now().timestamp();
    (-1_i64..=1).any(|offset| {
        let step = ((now / period_seconds) + offset).max(0) as u64;
        let expected = generate_totp_code(secret, digits, step);
        expected == code
    })
}

fn generate_totp_code(secret: &[u8], digits: u32, step: u64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("secret length is always valid");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let otp = binary % 10_u32.pow(digits);
    format!("{otp:0digits$}", digits = digits as usize)
}

pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    let mut rng = OsRng;
    (0..count)
        .map(|_| {
            let left: String = (&mut rng)
                .sample_iter(&Alphanumeric)
                .take(4)
                .map(char::from)
                .collect::<String>()
                .to_ascii_uppercase();
            let right: String = (&mut rng)
                .sample_iter(&Alphanumeric)
                .take(4)
                .map(char::from)
                .collect::<String>()
                .to_ascii_uppercase();
            format!("{left}-{right}")
        })
        .collect()
}

pub fn sign_ephemeral_url(
    secret: &str,
    purpose: &str,
    resource_id: Uuid,
    expires_at_epoch: i64,
) -> String {
    let payload = format!("{purpose}:{resource_id}:{expires_at_epoch}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("secret is valid");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_ephemeral_url(
    secret: &str,
    purpose: &str,
    resource_id: Uuid,
    expires_at_epoch: i64,
    signature: &str,
) -> bool {
    if Utc::now().timestamp() > expires_at_epoch {
        return false;
    }

    let expected = sign_ephemeral_url(secret, purpose, resource_id, expires_at_epoch);
    expected == signature
}

pub fn validate_csrf(cookies: &Cookies, headers: &HeaderMap) -> AppResult<()> {
    let csrf_cookie = cookies
        .get("csrf_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| AppError::unauthorized("csrf cookie is missing"))?;
    let csrf_header = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("X-CSRF-Token header is required"))?;

    if csrf_cookie == csrf_header {
        Ok(())
    } else {
        Err(AppError::unauthorized("csrf token mismatch"))
    }
}

pub async fn load_session_roles_and_scopes(
    pool: &sqlx::PgPool,
    account_id: Uuid,
) -> AppResult<(Vec<String>, Vec<String>)> {
    let role_rows = sqlx::query(
        r#"
        select r.code
        from iam.account_role ar
        join iam.role r on r.id = ar.role_id
        where ar.account_id = $1
          and (ar.expires_at is null or ar.expires_at > now())
          and r.deleted_at is null
        order by r.code
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    let roles: Vec<String> = role_rows
        .into_iter()
        .filter_map(|row| row.try_get::<String, _>("code").ok())
        .collect();

    let scope_rows = sqlx::query(
        r#"
        select distinct p.code
        from iam.account_role ar
        join iam.role_permission rp on rp.role_id = ar.role_id
        join iam.role r on r.id = ar.role_id
        join iam.permission p on p.id = rp.permission_id
        where ar.account_id = $1
          and (ar.expires_at is null or ar.expires_at > now())
          and r.deleted_at is null
        order by p.code
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    let mut scopes: Vec<String> = vec![
        "profile:read".to_string(),
        "profile:write".to_string(),
        "security:read".to_string(),
        "security:write".to_string(),
        "privacy:read".to_string(),
        "privacy:write".to_string(),
        "files:read".to_string(),
        "files:write".to_string(),
    ];

    let permission_scopes = scope_rows
        .into_iter()
        .filter_map(|row| row.try_get::<String, _>("code").ok())
        .collect::<Vec<_>>();

    scopes.extend(permission_scopes);
    scopes.sort();
    scopes.dedup();

    Ok((roles, scopes))
}

pub fn notification_payload(channel: &str, subject: &str, details: Value) -> Value {
    json!({
        "channel": channel,
        "subject": subject,
        "details": details
    })
}
