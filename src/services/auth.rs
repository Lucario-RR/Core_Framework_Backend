use chrono::{Duration, Utc};
use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::{
    api::contracts::{
        Acknowledgement, AuthSession, EmailVerificationConfirmRequest,
        EmailVerificationResendRequest, LoginRequest, MfaChallenge, MfaVerifyRequest,
        PasskeyAuthenticationOptions, PasskeyAuthenticationOptionsRequest,
        PasskeyAuthenticationVerifyRequest, PasswordChangeRequest, PasswordForgotRequest,
        PasswordPolicy, PasswordResetRequest, RegisterRequest,
    },
    auth::{self, notification_payload, AuthContext},
    error::{AppError, AppResult},
    request_context::RequestContext,
    services::shared,
    utils::{normalize_email, normalize_phone_number, normalize_username, validate_username},
    AppState,
};

pub enum LoginOutcome {
    Session(AuthSession),
    Challenge(MfaChallenge),
}

pub struct CreatedAccount {
    pub account_id: Uuid,
    pub primary_email_id: Uuid,
}

#[derive(Debug, Clone)]
struct RegistrationInviteUse {
    id: Uuid,
    role_codes: Vec<String>,
}

pub async fn register(
    state: &AppState,
    cookies: &Cookies,
    context: &RequestContext,
    request: RegisterRequest,
) -> AppResult<AuthSession> {
    if !shared::get_global_setting_bool(&state.pool, "registration.enabled").await? {
        return Err(AppError::forbidden(
            "public registration is currently disabled",
        ));
    }

    let invitation = if request.invitation_code.is_some() {
        Some(load_registration_invite_for_request(&state.pool, &request).await?)
    } else {
        None
    };

    if shared::get_global_setting_bool(&state.pool, "registration.invite_only").await? {
        if invitation.is_none() {
            return Err(AppError::forbidden(
                "invite-only registration is enabled and this endpoint requires an invitation code",
            ));
        }
    }

    let role_codes = invitation
        .as_ref()
        .map(|invite| invite.role_codes.clone())
        .unwrap_or_else(|| vec!["user".to_string()]);
    let invitation_id = invitation.as_ref().map(|invite| invite.id);

    let created = create_local_account(
        &state.pool,
        context,
        request,
        role_codes,
        None,
        Some("active".to_string()),
        invitation_id,
        false,
    )
    .await?;

    issue_session(state, cookies, context, created.account_id, false, 1).await
}

pub async fn register_admin_bootstrap(
    state: &AppState,
    cookies: &Cookies,
    context: &RequestContext,
    request: RegisterRequest,
) -> AppResult<AuthSession> {
    if !state.config.public_admin_bootstrap_enabled
        || !shared::get_global_setting_bool(&state.pool, "registration.bootstrap_admin_enabled")
            .await?
    {
        return Err(AppError::forbidden(
            "bootstrap admin registration is disabled",
        ));
    }

    let existing_admins = sqlx::query_scalar::<_, i64>(
        r#"
        select count(distinct ar.account_id)
        from iam.account_role ar
        join iam.role r on r.id = ar.role_id
        where r.code = 'admin'
          and (ar.expires_at is null or ar.expires_at > now())
          and r.deleted_at is null
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    if existing_admins > 0 {
        return Err(AppError::conflict(
            "an administrator account already exists",
        ));
    }

    let created = create_local_account(
        &state.pool,
        context,
        request,
        vec!["admin".to_string()],
        None,
        Some("active".to_string()),
        None,
        false,
    )
    .await?;

    issue_session(state, cookies, context, created.account_id, false, 2).await
}

pub async fn load_password_policy(pool: &PgPool) -> AppResult<PasswordPolicy> {
    let fallback_min_length = shared::get_global_setting_i64(pool, "auth.password.min_length")
        .await?
        .max(1);
    let mut policy = default_password_policy(fallback_min_length);
    let value = shared::get_global_setting_value(pool, "auth.password.policy").await?;

    if let Some(min_length) = value.get("minLength").and_then(Value::as_i64) {
        policy.min_length = min_length.max(1);
    }
    if let Some(require_letter) = value.get("requireLetter").and_then(Value::as_bool) {
        policy.require_letter = require_letter;
    }
    if let Some(require_number) = value.get("requireNumber").and_then(Value::as_bool) {
        policy.require_number = require_number;
    }
    if let Some(require_special) = value.get("requireSpecial").and_then(Value::as_bool) {
        policy.require_special = require_special;
    }
    if let Some(require_uppercase) = value.get("requireUppercase").and_then(Value::as_bool) {
        policy.require_uppercase = require_uppercase;
    }
    if let Some(require_lowercase) = value.get("requireLowercase").and_then(Value::as_bool) {
        policy.require_lowercase = require_lowercase;
    }
    if let Some(disallow_username) = value.get("disallowUsername").and_then(Value::as_bool) {
        policy.disallow_username = disallow_username;
    }
    if let Some(disallow_email) = value.get("disallowEmail").and_then(Value::as_bool) {
        policy.disallow_email = disallow_email;
    }

    Ok(policy)
}

pub async fn generate_initial_password(
    pool: &PgPool,
    username: Option<&str>,
    email: &str,
) -> AppResult<String> {
    let policy = load_password_policy(pool).await?;
    let emails = vec![email.to_string()];
    for _ in 0..50 {
        let candidate = random_password_candidate(&policy);
        if enforce_password_policy(&policy, &candidate, username, &emails).is_ok() {
            return Ok(candidate);
        }
    }

    Err(AppError::internal(
        "failed to generate a password that satisfies policy",
    ))
}

pub async fn validate_password_policy_for_account(
    pool: &PgPool,
    account_id: Uuid,
    password: &str,
) -> AppResult<()> {
    let policy = load_password_policy(pool).await?;
    let (username, emails) = load_password_policy_identifiers(pool, account_id).await?;
    enforce_password_policy(&policy, password, username.as_deref(), &emails)
}

fn default_password_policy(min_length: i64) -> PasswordPolicy {
    PasswordPolicy {
        min_length,
        require_letter: true,
        require_number: true,
        require_special: false,
        require_uppercase: false,
        require_lowercase: false,
        disallow_username: true,
        disallow_email: true,
    }
}

fn enforce_password_policy(
    policy: &PasswordPolicy,
    password: &str,
    username: Option<&str>,
    emails: &[String],
) -> AppResult<()> {
    let mut violations = Vec::new();
    if password.chars().count() < policy.min_length as usize {
        violations.push(json!({
            "code": "min_length",
            "message": format!("password must be at least {} characters", policy.min_length)
        }));
    }
    if policy.require_letter && !password.chars().any(|ch| ch.is_ascii_alphabetic()) {
        violations.push(json!({
            "code": "letter_required",
            "message": "password must include at least one letter"
        }));
    }
    if policy.require_number && !password.chars().any(|ch| ch.is_ascii_digit()) {
        violations.push(json!({
            "code": "number_required",
            "message": "password must include at least one number"
        }));
    }
    if policy.require_special && !password.chars().any(|ch| ch.is_ascii_punctuation()) {
        violations.push(json!({
            "code": "special_required",
            "message": "password must include at least one special character"
        }));
    }
    if policy.require_uppercase && !password.chars().any(|ch| ch.is_ascii_uppercase()) {
        violations.push(json!({
            "code": "uppercase_required",
            "message": "password must include at least one uppercase letter"
        }));
    }
    if policy.require_lowercase && !password.chars().any(|ch| ch.is_ascii_lowercase()) {
        violations.push(json!({
            "code": "lowercase_required",
            "message": "password must include at least one lowercase letter"
        }));
    }

    let lowered_password = password.to_ascii_lowercase();
    if policy.disallow_username {
        if let Some(username) = username
            .map(normalize_username)
            .filter(|value| !value.is_empty())
        {
            if lowered_password.contains(&username) {
                violations.push(json!({
                    "code": "contains_username",
                    "message": "password must not contain the username"
                }));
            }
        }
    }
    if policy.disallow_email {
        for email in emails {
            let normalized_email = normalize_email(email);
            let local_part = normalized_email.split('@').next().unwrap_or_default();
            if (!normalized_email.is_empty() && lowered_password.contains(&normalized_email))
                || (local_part.len() >= 3 && lowered_password.contains(local_part))
            {
                violations.push(json!({
                    "code": "contains_email",
                    "message": "password must not contain the email address"
                }));
                break;
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(AppError::validation("password does not meet policy")
            .with_details(json!({ "violations": violations })))
    }
}

fn random_password_candidate(policy: &PasswordPolicy) -> String {
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";
    const SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";
    const ALL: &[u8] =
        b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{}:,.?";

    let mut rng = OsRng;
    let mut chars = Vec::new();
    if policy.require_letter && !policy.require_uppercase && !policy.require_lowercase {
        chars.push(random_char(LOWER, &mut rng));
    }
    if policy.require_uppercase {
        chars.push(random_char(UPPER, &mut rng));
    }
    if policy.require_lowercase {
        chars.push(random_char(LOWER, &mut rng));
    }
    if policy.require_number {
        chars.push(random_char(DIGITS, &mut rng));
    }
    if policy.require_special {
        chars.push(random_char(SPECIAL, &mut rng));
    }

    let target_len = (policy.min_length as usize).max(16);
    while chars.len() < target_len {
        chars.push(random_char(ALL, &mut rng));
    }
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

fn random_char<R: Rng + ?Sized>(source: &[u8], rng: &mut R) -> char {
    source[rng.gen_range(0..source.len())] as char
}

async fn load_password_policy_identifiers(
    pool: &PgPool,
    account_id: Uuid,
) -> AppResult<(Option<String>, Vec<String>)> {
    let username = sqlx::query_scalar::<_, Option<String>>(
        "select public_handle from iam.account where id = $1",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?
    .flatten();

    let emails = sqlx::query_scalar::<_, String>(
        r#"
        select email
        from iam.account_email
        where account_id = $1
          and deleted_at is null
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    Ok((username, emails))
}

pub async fn login(
    state: &AppState,
    cookies: &Cookies,
    context: &RequestContext,
    request: LoginRequest,
) -> AppResult<LoginOutcome> {
    let login_identifier = resolve_login_identifier(&request)?;
    let normalized_email = normalize_email(&login_identifier);
    let normalized_phone = normalize_phone_number(&login_identifier);
    let normalized_username = normalize_username(&login_identifier);
    let subject_hash = auth::sha256_hex(&format!(
        "{}:{}:{}",
        normalized_email, normalized_phone, normalized_username
    ));
    enforce_lockout(&state.pool, "login", &subject_hash).await?;

    let row = sqlx::query(
        r#"
        with matched_account as (
            select a.id as account_id, 'email' as login_identifier_type
            from iam.account_email ae
            join iam.account a on a.id = ae.account_id
            where ae.normalized_email = $1
              and ae.deleted_at is null
              and ae.is_login_enabled = true
              and a.deleted_at is null

            union all

            select a.id as account_id, 'phone' as login_identifier_type
            from iam.account_phone ap
            join iam.account a on a.id = ap.account_id
            where ap.e164_phone_number = $2
              and ap.deleted_at is null
              and ap.is_login_enabled = true
              and a.deleted_at is null

            union all

            select a.id as account_id, 'username' as login_identifier_type
            from iam.account a
            where lower(a.public_handle) = $3
              and a.deleted_at is null
        )
        select
            a.id as account_id,
            a.status_code,
            ma.login_identifier_type,
            ae.id as email_id,
            ae.verification_status,
            pc.password_hash,
            pc.password_version,
            pc.must_rotate
        from matched_account ma
        join iam.account a on a.id = ma.account_id
        left join iam.account_email ae
            on ae.account_id = a.id
           and ae.is_primary_for_account = true
           and ae.deleted_at is null
        join auth.authenticator au on au.account_id = a.id and au.authenticator_type = 'PASSWORD' and au.revoked_at is null
        join auth.password_credential pc on pc.authenticator_id = au.id
        order by case ma.login_identifier_type
            when 'email' then 1
            when 'phone' then 2
            else 3
        end
        limit 1
        "#,
    )
    .bind(&normalized_email)
    .bind(&normalized_phone)
    .bind(&normalized_username)
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        register_login_failure(&state.pool, "login", &subject_hash).await?;
        return Err(AppError::unauthorized("login or password is invalid"));
    };

    let account_id: Uuid = row.try_get("account_id")?;
    let password_hash: String = row.try_get("password_hash")?;
    let status_code: String = row.try_get("status_code")?;
    let login_identifier_type: String = row.try_get("login_identifier_type")?;

    enforce_account_access(&state.pool, account_id, &status_code).await?;

    if !auth::verify_password(&request.password, &password_hash)? {
        register_login_failure(&state.pool, "login", &subject_hash).await?;
        shared::record_security_event(
            &state.pool,
            Some(account_id),
            "login_failure",
            "medium",
            Some("Invalid password supplied.".to_string()),
            context.ip_address.as_deref(),
            context.user_agent.as_deref(),
            None,
            json!({"loginIdentifierType": login_identifier_type}),
            Some(&context.request_id),
        )
        .await?;
        return Err(AppError::unauthorized("login or password is invalid"));
    }

    clear_lockout_failures(&state.pool, "login", &subject_hash).await?;

    let security = shared::load_security_summary(&state.pool, account_id).await?;
    if security.totp_enabled {
        let available_factors = available_mfa_factors(&state.pool, account_id).await?;
        if !available_factors.is_empty() {
            let challenge_id = Uuid::new_v4();
            let expires_at = Utc::now() + Duration::minutes(10);

            sqlx::query(
                r#"
                insert into auth.login_challenge (
                    id, account_id, challenge_type, available_factors_json, details_json, expires_at, created_at
                )
                values ($1, $2, 'MFA_REQUIRED', $3, $4, $5, now())
                "#,
            )
            .bind(challenge_id)
            .bind(account_id)
            .bind(json!(available_factors))
            .bind(json!({
                "rememberMe": request.remember_me.unwrap_or(false),
                "ipAddress": context.ip_address,
                "userAgent": context.user_agent
            }))
            .bind(expires_at)
            .execute(&state.pool)
            .await?;

            return Ok(LoginOutcome::Challenge(MfaChallenge {
                challenge_id,
                available_factors,
                expires_at,
            }));
        }
    }

    let session = issue_session(
        state,
        cookies,
        context,
        account_id,
        request.remember_me.unwrap_or(false),
        1,
    )
    .await?;

    Ok(LoginOutcome::Session(session))
}

fn resolve_login_identifier(request: &LoginRequest) -> AppResult<String> {
    [
        request.login.as_deref(),
        request.username.as_deref(),
        request.email.as_deref(),
        request.phone_number.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .find(|value| !value.is_empty())
    .map(ToOwned::to_owned)
    .ok_or_else(|| AppError::validation("login, username, email, or phoneNumber is required"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login_request(
        login: Option<&str>,
        username: Option<&str>,
        email: Option<&str>,
        phone_number: Option<&str>,
    ) -> LoginRequest {
        LoginRequest {
            login: login.map(str::to_string),
            email: email.map(str::to_string),
            username: username.map(str::to_string),
            phone_number: phone_number.map(str::to_string),
            password: "ValidPassword123".to_string(),
            remember_me: None,
        }
    }

    #[test]
    fn resolve_login_identifier_accepts_phone_number_field() {
        let request = login_request(None, None, None, Some("+447700900123"));

        assert_eq!(resolve_login_identifier(&request).unwrap(), "+447700900123");
    }

    #[test]
    fn resolve_login_identifier_accepts_phone_alias() {
        let request: LoginRequest = serde_json::from_value(json!({
            "phone": "+447700900124",
            "password": "ValidPassword123"
        }))
        .unwrap();

        assert_eq!(resolve_login_identifier(&request).unwrap(), "+447700900124");
    }

    #[test]
    fn resolve_login_identifier_accepts_preferred_login_field() {
        let request: LoginRequest = serde_json::from_value(json!({
            "login": "alex@example.com",
            "password": "ValidPassword123"
        }))
        .unwrap();

        assert_eq!(
            resolve_login_identifier(&request).unwrap(),
            "alex@example.com"
        );
    }

    #[test]
    fn resolve_login_identifier_skips_blank_preferred_fields() {
        let request = login_request(Some(" "), Some("alex"), Some("alex@example.com"), None);

        assert_eq!(resolve_login_identifier(&request).unwrap(), "alex");
    }
}

async fn load_registration_invite_for_request(
    pool: &PgPool,
    request: &RegisterRequest,
) -> AppResult<RegistrationInviteUse> {
    let code = request
        .invitation_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::validation("invitationCode is required"))?;
    let code_hash = auth::sha256_hex(code);

    let row = sqlx::query(
        r#"
        select id, normalized_email, role_codes_json
        from auth.registration_invite
        where invite_code_hash = $1
          and status = 'active'
          and revoked_at is null
          and (expires_at is null or expires_at > now())
          and use_count < max_uses
        limit 1
        "#,
    )
    .bind(code_hash)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::conflict("invitation code is invalid or expired"))?;

    let id: Uuid = row.try_get("id")?;
    let invited_email: Option<String> = row.try_get("normalized_email")?;
    let requested_email = normalize_email(&request.email);
    if invited_email
        .as_deref()
        .map(|email| email != requested_email)
        .unwrap_or(false)
    {
        return Err(AppError::forbidden(
            "invitation code is not valid for this email address",
        ));
    }

    let role_codes_json: Value = row.try_get("role_codes_json")?;
    let mut role_codes = role_codes_json
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if role_codes.is_empty() {
        role_codes.push("user".to_string());
    }

    Ok(RegistrationInviteUse { id, role_codes })
}

pub async fn refresh_session(
    state: &AppState,
    cookies: &Cookies,
    headers: &http::HeaderMap,
    context: &RequestContext,
) -> AppResult<AuthSession> {
    auth::validate_csrf(cookies, headers)?;
    let refresh_token = cookies
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| AppError::unauthorized("refresh cookie is missing"))?;
    let refresh_hash = auth::sha256_hex(&refresh_token);

    let row = sqlx::query(
        r#"
        select id, account_id, remember_me, authenticated_aal
        from auth.session
        where refresh_token_hash = $1
          and revoked_at is null
          and absolute_expires_at > now()
        limit 1
        "#,
    )
    .bind(refresh_hash)
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        return Err(AppError::unauthorized("refresh session is invalid"));
    };

    let session_id: Uuid = row.try_get("id")?;
    let account_id: Uuid = row.try_get("account_id")?;
    let remember_me: bool = row.try_get("remember_me")?;
    let aal: i16 = row.try_get("authenticated_aal")?;

    let idle_timeout =
        shared::get_global_setting_i64(&state.pool, "auth.session.idle_timeout_seconds").await?;
    let new_refresh_token = auth::generate_token(48);
    let new_csrf_token = auth::generate_token(24);

    sqlx::query(
        r#"
        update auth.session
        set refresh_token_hash = $2,
            last_seen_at = now(),
            idle_expires_at = now() + make_interval(secs => $3::integer)
        where id = $1
        "#,
    )
    .bind(session_id)
    .bind(auth::sha256_hex(&new_refresh_token))
    .bind(idle_timeout as i32)
    .execute(&state.pool)
    .await?;

    auth::set_auth_cookies(cookies, &state.config, &new_refresh_token, &new_csrf_token);
    complete_session_issue(
        state,
        account_id,
        session_id,
        aal as i32,
        remember_me,
        context,
    )
    .await
}

pub async fn logout(
    state: &AppState,
    headers: &http::HeaderMap,
    cookies: &Cookies,
    context: &RequestContext,
) -> AppResult<()> {
    let session_id = if headers.get(http::header::AUTHORIZATION).is_some() {
        Some(auth::require_auth(state, headers).await?.session_id)
    } else if let Some(refresh_cookie) = cookies.get("refresh_token") {
        let refresh_hash = auth::sha256_hex(refresh_cookie.value());
        sqlx::query_scalar::<_, Uuid>(
            r#"
            select id
            from auth.session
            where refresh_token_hash = $1
              and revoked_at is null
            limit 1
            "#,
        )
        .bind(refresh_hash)
        .fetch_optional(&state.pool)
        .await?
    } else {
        None
    };

    if let Some(session_id) = session_id {
        sqlx::query(
            r#"
            update auth.session
            set revoked_at = now(),
                revoke_reason_code = 'logout'
            where id = $1
            "#,
        )
        .bind(session_id)
        .execute(&state.pool)
        .await?;

        shared::record_security_event(
            &state.pool,
            None,
            "session_revoked",
            "low",
            Some("Session revoked during logout.".to_string()),
            context.ip_address.as_deref(),
            context.user_agent.as_deref(),
            None,
            json!({"sessionId": session_id}),
            Some(&context.request_id),
        )
        .await?;
    }

    auth::clear_auth_cookies(cookies);
    Ok(())
}

pub async fn change_password(
    state: &AppState,
    auth_context: &AuthContext,
    context: &RequestContext,
    request: PasswordChangeRequest,
) -> AppResult<Acknowledgement> {
    validate_password_policy_for_account(
        &state.pool,
        auth_context.account_id,
        &request.new_password,
    )
    .await?;

    let row = sqlx::query(
        r#"
        select
            au.id as authenticator_id,
            pc.password_hash,
            pc.password_version,
            pc.hash_algorithm,
            pc.hash_parameters_json,
            pc.salt_value,
            pc.changed_at
        from auth.authenticator au
        join auth.password_credential pc on pc.authenticator_id = au.id
        where au.account_id = $1
          and au.authenticator_type = 'PASSWORD'
          and au.revoked_at is null
        limit 1
        "#,
    )
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::conflict("password credential is not enrolled"))?;

    let authenticator_id: Uuid = row.try_get("authenticator_id")?;
    let current_hash: String = row.try_get("password_hash")?;
    let current_version: i32 = row.try_get("password_version")?;
    let changed_at = row.try_get::<chrono::DateTime<Utc>, _>("changed_at")?;
    let hash_algorithm: String = row.try_get("hash_algorithm")?;
    let hash_parameters_json: Value = row.try_get("hash_parameters_json")?;
    let salt_value: Vec<u8> = row.try_get("salt_value")?;

    if !auth::verify_password(&request.current_password, &current_hash)? {
        return Err(AppError::unauthorized("current password is invalid"));
    }

    if auth::verify_password(&request.new_password, &current_hash)? {
        return Err(AppError::conflict(
            "new password must differ from the current password",
        ));
    }

    let history_limit =
        shared::get_global_setting_i64(&state.pool, "auth.password.history_count").await?;
    let history_rows = sqlx::query_scalar::<_, String>(
        r#"
        select password_hash
        from auth.password_history
        where account_id = $1
        order by password_version desc
        limit $2
        "#,
    )
    .bind(auth_context.account_id)
    .bind(history_limit)
    .fetch_all(&state.pool)
    .await?;

    if history_rows
        .into_iter()
        .any(|hash| auth::verify_password(&request.new_password, &hash).unwrap_or(false))
    {
        return Err(AppError::conflict(
            "new password cannot reuse a recent password",
        ));
    }

    let new_password = auth::hash_password(&request.new_password)?;
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        r#"
        insert into auth.password_history (
            id, account_id, password_hash, salt_value, hash_algorithm, hash_parameters_json, password_version, valid_from, valid_to, stored_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(auth_context.account_id)
    .bind(&current_hash)
    .bind(salt_value)
    .bind(hash_algorithm)
    .bind(hash_parameters_json)
    .bind(current_version)
    .bind(changed_at)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        update auth.password_credential
        set password_hash = $2,
            salt_value = $3,
            hash_parameters_json = $4,
            password_version = password_version + 1,
            changed_at = now(),
            must_rotate = false
        where authenticator_id = $1
        "#,
    )
    .bind(authenticator_id)
    .bind(new_password.password_hash)
    .bind(new_password.salt_value)
    .bind(new_password.hash_parameters_json)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        update auth.session
        set revoked_at = now(),
            revoke_reason_code = 'password_changed'
        where account_id = $1
          and id <> $2
          and revoked_at is null
        "#,
    )
    .bind(auth_context.account_id)
    .bind(auth_context.session_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    shared::record_audit_log(
        &state.pool,
        Some(auth_context.account_id),
        "auth.password.changed",
        "account",
        Some(auth_context.account_id),
        Some("Password changed by the account owner.".to_string()),
        json!({}),
        Some(&context.request_id),
    )
    .await?;
    shared::record_security_event(
        &state.pool,
        Some(auth_context.account_id),
        "password_changed",
        "medium",
        Some("Password changed successfully.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        None,
        json!({}),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Password changed successfully.".to_string()),
    })
}

pub async fn start_password_reset(
    state: &AppState,
    context: &RequestContext,
    request: PasswordForgotRequest,
) -> AppResult<Acknowledgement> {
    let normalized_email = normalize_email(&request.email);
    let row = sqlx::query(
        r#"
        select a.id as account_id, ae.id as email_id, coalesce(pc.password_version, 1) as password_version
        from iam.account_email ae
        join iam.account a on a.id = ae.account_id
        left join auth.authenticator au on au.account_id = a.id and au.authenticator_type = 'PASSWORD' and au.revoked_at is null
        left join auth.password_credential pc on pc.authenticator_id = au.id
        where ae.normalized_email = $1
          and ae.deleted_at is null
          and ae.is_login_enabled = true
        limit 1
        "#,
    )
    .bind(&normalized_email)
    .fetch_optional(&state.pool)
    .await?;

    if let Some(row) = row {
        let account_id: Uuid = row.try_get("account_id")?;
        let email_id: Uuid = row.try_get("email_id")?;
        let password_version: i32 = row.try_get("password_version")?;
        let reset_token = format!("reset_{}", auth::generate_token(36));
        let challenge_hash = auth::sha256_hex(&reset_token);
        let ttl =
            shared::get_global_setting_i64(&state.pool, "auth.password.reset_ttl_seconds").await?;

        sqlx::query(
            r#"
            insert into auth.password_reset_challenge (
                id, account_id, requested_email_id, password_version_at_issue, challenge_hash, expires_at,
                request_ip, request_user_agent, created_at
            )
            values ($1, $2, $3, $4, $5, now() + make_interval(secs => $6::integer), nullif($7, '')::inet, $8, now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(email_id)
        .bind(password_version)
        .bind(challenge_hash)
        .bind(ttl as i32)
        .bind(context.ip_address.as_deref().unwrap_or_default())
        .bind(context.user_agent.as_deref())
        .execute(&state.pool)
        .await?;

        shared::queue_notification(
            &state.pool,
            Some(account_id),
            "password_reset_requested",
            "email",
            Some("Password reset requested".to_string()),
            notification_payload(
                "email",
                "password-reset",
                json!({
                    "email": request.email,
                    "resetToken": reset_token,
                    "expiresInSeconds": ttl
                }),
            ),
        )
        .await?;
        shared::record_security_event(
            &state.pool,
            Some(account_id),
            "password_reset_requested",
            "medium",
            Some("Password reset flow started.".to_string()),
            context.ip_address.as_deref(),
            context.user_agent.as_deref(),
            None,
            json!({"email": request.email}),
            Some(&context.request_id),
        )
        .await?;
    }

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("If the account exists, reset instructions were queued.".to_string()),
    })
}

pub async fn complete_password_reset(
    state: &AppState,
    context: &RequestContext,
    request: PasswordResetRequest,
) -> AppResult<()> {
    let token_hash = auth::sha256_hex(&request.reset_token);
    let row = sqlx::query(
        r#"
        select
            prc.id as challenge_id,
            prc.account_id,
            prc.password_version_at_issue,
            au.id as authenticator_id,
            pc.password_version
        from auth.password_reset_challenge prc
        join auth.authenticator au on au.account_id = prc.account_id and au.authenticator_type = 'PASSWORD' and au.revoked_at is null
        join auth.password_credential pc on pc.authenticator_id = au.id
        where prc.challenge_hash = $1
          and prc.consumed_at is null
          and prc.invalidated_at is null
          and prc.expires_at > now()
        limit 1
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::conflict("password reset token is invalid or expired"))?;

    let challenge_id: Uuid = row.try_get("challenge_id")?;
    let account_id: Uuid = row.try_get("account_id")?;
    let issued_version: i32 = row.try_get("password_version_at_issue")?;
    let current_version: i32 = row.try_get("password_version")?;
    let authenticator_id: Uuid = row.try_get("authenticator_id")?;

    validate_password_policy_for_account(&state.pool, account_id, &request.new_password).await?;

    if issued_version != current_version {
        return Err(AppError::conflict("password reset token is stale"));
    }

    let new_password = auth::hash_password(&request.new_password)?;
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        r#"
        update auth.password_credential
        set password_hash = $2,
            salt_value = $3,
            hash_parameters_json = $4,
            password_version = password_version + 1,
            changed_at = now(),
            must_rotate = false
        where authenticator_id = $1
        "#,
    )
    .bind(authenticator_id)
    .bind(new_password.password_hash)
    .bind(new_password.salt_value)
    .bind(new_password.hash_parameters_json)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        update auth.password_reset_challenge
        set consumed_at = now()
        where id = $1
        "#,
    )
    .bind(challenge_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        update auth.session
        set revoked_at = now(),
            revoke_reason_code = 'password_reset'
        where account_id = $1
          and revoked_at is null
        "#,
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    shared::record_security_event(
        &state.pool,
        Some(account_id),
        "password_reset_completed",
        "high",
        Some("Password reset completed.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        None,
        json!({}),
        Some(&context.request_id),
    )
    .await?;

    Ok(())
}

pub async fn verify_email_challenge(
    state: &AppState,
    context: &RequestContext,
    request: EmailVerificationConfirmRequest,
) -> AppResult<Acknowledgement> {
    let token_hash = auth::sha256_hex(&request.verification_token);
    let row = sqlx::query(
        r#"
        select
            evc.id,
            evc.account_email_id,
            evc.purpose_code,
            ae.account_id,
            ae.is_primary_for_account
        from auth.email_verification_challenge evc
        join iam.account_email ae on ae.id = evc.account_email_id
        where evc.challenge_hash = $1
          and evc.consumed_at is null
          and evc.invalidated_at is null
          and evc.expires_at > now()
        limit 1
        "#,
    )
    .bind(token_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::conflict("verification token is invalid or expired"))?;

    let challenge_id: Uuid = row.try_get("id")?;
    let account_email_id: Uuid = row.try_get("account_email_id")?;
    let purpose_code: String = row.try_get("purpose_code")?;
    let account_id: Uuid = row.try_get("account_id")?;

    let mut tx = state.pool.begin().await?;
    sqlx::query("update auth.email_verification_challenge set consumed_at = now() where id = $1")
        .bind(challenge_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        r#"
        update iam.account_email
        set verification_status = 'verified',
            verified_at = now(),
            updated_at = now()
        where id = $1
        "#,
    )
    .bind(account_email_id)
    .execute(&mut *tx)
    .await?;

    if purpose_code == "CHANGE_OLD" {
        sqlx::query(
            r#"
            update auth.account_email_change_request
            set old_address_confirmed_at = now()
            where old_account_email_id = $1
              and status = 'pending'
              and expires_at > now()
            "#,
        )
        .bind(account_email_id)
        .execute(&mut *tx)
        .await?;
    }

    if purpose_code == "CHANGE_NEW" {
        sqlx::query(
            r#"
            update auth.account_email_change_request
            set new_address_confirmed_at = now()
            where account_id = $1
              and status = 'pending'
              and expires_at > now()
              and new_normalized_email = (
                    select normalized_email from iam.account_email where id = $2
              )
            "#,
        )
        .bind(account_id)
        .bind(account_email_id)
        .execute(&mut *tx)
        .await?;
    }

    if let Some(change_request) = sqlx::query(
        r#"
        select id, new_normalized_email
        from auth.account_email_change_request
        where account_id = $1
          and status = 'pending'
          and old_address_confirmed_at is not null
          and new_address_confirmed_at is not null
        order by created_at desc
        limit 1
        "#,
    )
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        let change_request_id: Uuid = change_request.try_get("id")?;
        let new_normalized_email: String = change_request.try_get("new_normalized_email")?;

        sqlx::query(
            r#"
            update iam.account_email
            set is_primary_for_account = false,
                updated_at = now()
            where account_id = $1
              and deleted_at is null
            "#,
        )
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            update iam.account_email
            set is_primary_for_account = true,
                is_login_enabled = true,
                verification_status = 'verified',
                verified_at = coalesce(verified_at, now()),
                updated_at = now()
            where account_id = $1
              and normalized_email = $2
              and deleted_at is null
            "#,
        )
        .bind(account_id)
        .bind(new_normalized_email)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            update auth.account_email_change_request
            set status = 'completed',
                completed_at = now()
            where id = $1
            "#,
        )
        .bind(change_request_id)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        r#"
        update iam.account
        set activated_at = coalesce(activated_at, now()),
            updated_at = now()
        where id = $1
        "#,
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    shared::record_security_event(
        &state.pool,
        Some(account_id),
        "email_verified",
        "low",
        Some("Email address verified.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        None,
        json!({"accountEmailId": account_email_id}),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Email verified successfully.".to_string()),
    })
}

pub async fn resend_primary_email_verification(
    state: &AppState,
    context: &RequestContext,
    request: EmailVerificationResendRequest,
) -> AppResult<Acknowledgement> {
    let normalized_email = normalize_email(&request.email);
    let row = sqlx::query(
        r#"
        select ae.id, ae.account_id
        from iam.account_email ae
        where ae.normalized_email = $1
          and ae.deleted_at is null
        limit 1
        "#,
    )
    .bind(normalized_email)
    .fetch_optional(&state.pool)
    .await?;

    if let Some(row) = row {
        let account_email_id: Uuid = row.try_get("id")?;
        let account_id: Uuid = row.try_get("account_id")?;
        enqueue_email_verification(
            &state.pool,
            account_id,
            account_email_id,
            request
                .purpose
                .unwrap_or_else(|| "registration".to_string()),
            context,
        )
        .await?;
    }

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Verification challenge accepted for delivery.".to_string()),
    })
}

pub async fn verify_mfa_challenge(
    state: &AppState,
    cookies: &Cookies,
    context: &RequestContext,
    request: MfaVerifyRequest,
) -> AppResult<AuthSession> {
    let row = sqlx::query(
        r#"
        select id, account_id, available_factors_json, details_json
        from auth.login_challenge
        where id = $1
          and completed_at is null
          and expires_at > now()
        limit 1
        "#,
    )
    .bind(request.challenge_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("login challenge is invalid or expired"))?;

    let challenge_id: Uuid = row.try_get("id")?;
    let account_id: Uuid = row.try_get("account_id")?;
    let details_json: Value = row.try_get("details_json")?;
    let code = request.code.clone().unwrap_or_default();

    match request.factor_type.as_str() {
        "totp" => verify_totp_factor(&state.pool, account_id, &code).await?,
        "recovery_code" => verify_recovery_code(&state.pool, account_id, &code).await?,
        _ => {
            return Err(AppError::validation(
                "factorType must be totp or recovery_code",
            ))
        }
    }

    sqlx::query("update auth.login_challenge set completed_at = now() where id = $1")
        .bind(challenge_id)
        .execute(&state.pool)
        .await?;

    let remember_me = details_json
        .get("rememberMe")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    issue_session(state, cookies, context, account_id, remember_me, 2).await
}

pub async fn create_passkey_authentication_options(
    state: &AppState,
    request: PasskeyAuthenticationOptionsRequest,
) -> AppResult<PasskeyAuthenticationOptions> {
    if !shared::get_global_setting_bool(&state.pool, "auth.passkey.enabled").await? {
        return Err(AppError::forbidden("passkey authentication is disabled"));
    }

    let account_id = if let Some(email) = request.email.as_ref() {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            select account_id
            from iam.account_email
            where normalized_email = $1
              and deleted_at is null
            limit 1
            "#,
        )
        .bind(normalize_email(email))
        .fetch_optional(&state.pool)
        .await?
    } else {
        None
    };

    let authentication_id = Uuid::new_v4();
    let challenge = auth::generate_token(24);
    let public_key = json!({
        "challenge": challenge,
        "timeout": 60000,
        "rpId": "localhost",
        "userVerification": "preferred"
    });

    sqlx::query(
        r#"
        insert into auth.passkey_authentication_challenge (id, account_id, challenge_json, expires_at, created_at)
        values ($1, $2, $3, now() + interval '10 minutes', now())
        "#,
    )
    .bind(authentication_id)
    .bind(account_id)
    .bind(json!({ "challenge": public_key.get("challenge"), "publicKey": public_key }))
    .execute(&state.pool)
    .await?;

    Ok(PasskeyAuthenticationOptions {
        authentication_id,
        public_key,
    })
}

pub async fn verify_passkey_authentication(
    state: &AppState,
    cookies: &Cookies,
    context: &RequestContext,
    request: PasskeyAuthenticationVerifyRequest,
) -> AppResult<AuthSession> {
    let row = sqlx::query(
        r#"
        select id, account_id, challenge_json
        from auth.passkey_authentication_challenge
        where id = $1
          and verified_at is null
          and expires_at > now()
        limit 1
        "#,
    )
    .bind(request.authentication_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("passkey authentication challenge is invalid"))?;

    let challenge_id: Uuid = row.try_get("id")?;
    let hinted_account_id: Option<Uuid> = row.try_get("account_id")?;
    let credential_id = request
        .credential
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::validation("credential.id is required"))?;

    let account_id = if let Some(account_id) = hinted_account_id {
        let exists = sqlx::query_scalar::<_, bool>(
            r#"
            select exists (
                select 1
                from auth.authenticator a
                join auth.passkey_credential pk on pk.authenticator_id = a.id
                where a.account_id = $1
                  and pk.credential_id = $2
                  and a.revoked_at is null
            )
            "#,
        )
        .bind(account_id)
        .bind(credential_id)
        .fetch_one(&state.pool)
        .await?;

        if !exists {
            return Err(AppError::unauthorized(
                "passkey credential is not registered",
            ));
        }

        account_id
    } else {
        sqlx::query_scalar::<_, Uuid>(
            r#"
            select a.account_id
            from auth.authenticator a
            join auth.passkey_credential pk on pk.authenticator_id = a.id
            where pk.credential_id = $1
              and a.revoked_at is null
            limit 1
            "#,
        )
        .bind(credential_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::unauthorized("passkey credential is not registered"))?
    };

    sqlx::query(
        "update auth.passkey_authentication_challenge set verified_at = now() where id = $1",
    )
    .bind(challenge_id)
    .execute(&state.pool)
    .await?;

    issue_session(state, cookies, context, account_id, false, 2).await
}

pub async fn create_local_account(
    pool: &PgPool,
    context: &RequestContext,
    request: RegisterRequest,
    role_codes: Vec<String>,
    created_by_account_id: Option<Uuid>,
    requested_status: Option<String>,
    registration_invite_id: Option<Uuid>,
    require_password_change: bool,
) -> AppResult<CreatedAccount> {
    if created_by_account_id.is_none() && request.accepted_legal_documents.is_empty() {
        return Err(AppError::validation(
            "acceptedLegalDocuments must contain at least one document",
        ));
    }

    let account_id = Uuid::new_v4();
    let primary_email_id = Uuid::new_v4();
    let normalized_email = normalize_email(&request.email);
    let username = validate_username(&request.username)?;
    let normalized_phone = request
        .primary_phone
        .as_ref()
        .map(|value| normalize_phone_number(value));

    let policy = load_password_policy(pool).await?;
    enforce_password_policy(
        &policy,
        &request.password,
        Some(&username),
        &[request.email.clone()],
    )?;

    let existing = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from iam.account_email
            where normalized_email = $1
              and deleted_at is null
        )
        "#,
    )
    .bind(&normalized_email)
    .fetch_one(pool)
    .await?;

    if existing {
        return Err(AppError::conflict(
            "an account already exists for that email address",
        ));
    }

    let username_exists = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from iam.account
            where lower(public_handle) = $1
              and deleted_at is null
        )
        "#,
    )
    .bind(&username)
    .fetch_one(pool)
    .await?;

    if username_exists {
        return Err(AppError::conflict("username is already in use"));
    }

    if let Some(primary_phone) = normalized_phone.as_ref() {
        let phone_exists = sqlx::query_scalar::<_, bool>(
            r#"
            select exists (
                select 1
                from iam.account_phone
                where e164_phone_number = $1
                  and deleted_at is null
                  and is_login_enabled = true
            )
            "#,
        )
        .bind(primary_phone)
        .fetch_one(pool)
        .await?;

        if phone_exists {
            return Err(AppError::conflict(
                "an account already exists for that phone number",
            ));
        }
    }

    enforce_email_domain_rules(pool, &normalized_email).await?;

    let password = auth::hash_password(&request.password)?;
    let password_authenticator_id = Uuid::new_v4();
    let now = Utc::now();
    let status_code = requested_status.unwrap_or_else(|| "active".to_string());
    let require_mfa_enrollment = mfa_enrollment_required_for_new_account(pool, &role_codes).await?;

    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        insert into iam.account (
            id, public_handle, status_code, created_by_account_id, activated_at,
            username_changed_at, created_at, updated_at
        )
        values ($1, $2, $3, $4, case when $3 = 'active' then now() else null end, now(), now(), now())
        "#,
    )
    .bind(account_id)
    .bind(&username)
    .bind(&status_code)
    .bind(created_by_account_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into iam.account_profile (
            account_id, display_name, locale, timezone_name, default_currency, created_at, updated_at
        )
        values ($1, $2, 'en-GB', 'Europe/London', 'GBP', now(), now())
        "#,
    )
    .bind(account_id)
    .bind(request.display_name.trim())
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into iam.account_email (
            id, account_id, email, normalized_email, label, is_login_enabled, is_primary_for_account,
            verification_status, created_at, updated_at
        )
        values ($1, $2, $3, $4, 'primary', true, true, 'pending', now(), now())
        "#,
    )
    .bind(primary_email_id)
    .bind(account_id)
    .bind(request.email.trim())
    .bind(&normalized_email)
    .execute(&mut *tx)
    .await?;

    if let Some(primary_phone) = normalized_phone {
        sqlx::query(
            r#"
            insert into iam.account_phone (
                id, account_id, e164_phone_number, label, is_sms_enabled, is_primary_for_account,
                is_login_enabled, verification_status, created_at, updated_at
            )
            values ($1, $2, $3, 'primary', false, true, true, 'pending', now(), now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(primary_phone)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        r#"
        insert into auth.authenticator (
            id, account_id, authenticator_type, usage_type, display_label, status, enrolled_at, confirmed_at, created_at
        )
        values ($1, $2, 'PASSWORD', 'PRIMARY', 'Account password', 'active', now(), now(), now())
        "#,
    )
    .bind(password_authenticator_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into auth.password_credential (
            authenticator_id, password_hash, salt_value, hash_algorithm, hash_parameters_json,
            password_version, changed_at, must_rotate
        )
        values ($1, $2, $3, 'ARGON2ID', $4, 1, now(), $5)
        "#,
    )
    .bind(password_authenticator_id)
    .bind(password.password_hash)
    .bind(password.salt_value)
    .bind(password.hash_parameters_json)
    .bind(require_password_change)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into iam.account_status_history (
            id, account_id, from_status_code, to_status_code, reason_code, reason_text, changed_by_account_id, request_id, changed_at
        )
        values ($1, $2, null, $3, $4, $5, $6, $7, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(&status_code)
    .bind(if created_by_account_id.is_some() {
        "ADMIN_CREATED"
    } else {
        "REGISTERED"
    })
    .bind(Some("Account created".to_string()))
    .bind(created_by_account_id)
    .bind(Some(context.request_id.as_str()))
    .execute(&mut *tx)
    .await?;

    for role_code in role_codes {
        sqlx::query(
            r#"
            insert into iam.account_role (account_id, role_id, granted_by_account_id, granted_at)
            select $1, r.id, $2, now()
            from iam.role r
            where r.code = $3
              and r.deleted_at is null
            on conflict do nothing
            "#,
        )
        .bind(account_id)
        .bind(created_by_account_id)
        .bind(role_code)
        .execute(&mut *tx)
        .await?;
    }

    if let Some(invite_id) = registration_invite_id {
        let affected = sqlx::query(
            r#"
            update auth.registration_invite
            set use_count = use_count + 1,
                last_used_at = now(),
                consumed_at = case
                    when use_count + 1 >= max_uses then now()
                    else consumed_at
                end,
                status = case
                    when use_count + 1 >= max_uses then 'consumed'
                    else status
                end
            where id = $1
              and status = 'active'
              and revoked_at is null
              and (expires_at is null or expires_at > now())
              and use_count < max_uses
            "#,
        )
        .bind(invite_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(AppError::conflict("invitation code is no longer valid"));
        }
    }

    if require_mfa_enrollment {
        sqlx::query(
            r#"
            insert into ops.account_setting (id, account_id, setting_key, value_json, updated_at)
            values ($1, $2, 'security.require_mfa_enrollment', $3, now())
            on conflict (account_id, setting_key)
            do update set value_json = excluded.value_json, updated_at = now()
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(json!(true))
        .execute(&mut *tx)
        .await?;
    }

    for document in request.accepted_legal_documents {
        let notice_type = match document.document_key.as_str() {
            "terms_of_service" => "TERMS",
            "privacy_policy" => "PRIVACY",
            "cookie_policy" => "COOKIE",
            _ => return Err(AppError::validation("unsupported legal document key")),
        };

        sqlx::query(
            r#"
            insert into privacy.consent_record (
                id, account_id, purpose_code, notice_version_id, consent_status, captured_via, evidence_json, captured_at
            )
            values (
                $1,
                $2,
                $3,
                (
                    select id
                    from privacy.privacy_notice_version
                    where notice_type = $4 and version_label = $5
                    order by published_at desc
                    limit 1
                ),
                'granted',
                'api',
                $6,
                now()
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(document.document_key)
        .bind(notice_type)
        .bind(document.version)
        .bind(json!({"source": "registration"}))
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    enqueue_email_verification(
        pool,
        account_id,
        primary_email_id,
        "registration".to_string(),
        context,
    )
    .await?;
    shared::record_audit_log(
        pool,
        created_by_account_id,
        "account.created",
        "account",
        Some(account_id),
        Some("Account created.".to_string()),
        json!({
            "bootstrap": created_by_account_id.is_none(),
            "mfaEnrollmentRequired": require_mfa_enrollment,
            "registrationInviteId": registration_invite_id,
            "username": username
        }),
        Some(&context.request_id),
    )
    .await?;
    shared::record_security_event(
        pool,
        Some(account_id),
        "login_success",
        "low",
        Some("Account registered.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        None,
        json!({ "accountCreatedAt": now }),
        Some(&context.request_id),
    )
    .await?;

    Ok(CreatedAccount {
        account_id,
        primary_email_id,
    })
}

async fn mfa_enrollment_required_for_new_account(
    pool: &PgPool,
    role_codes: &[String],
) -> AppResult<bool> {
    let global_all_users =
        shared::get_global_setting_bool(pool, "auth.mfa.required_for_all_users").await?;
    let global_admins =
        shared::get_global_setting_bool(pool, "auth.mfa.required_for_admins").await?;
    let role_requires_mfa = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from iam.role
            where code = any($1::text[])
              and deleted_at is null
              and requires_mfa = true
        )
        "#,
    )
    .bind(role_codes.to_vec())
    .fetch_one(pool)
    .await?;
    let is_admin = role_codes.iter().any(|role| role == "admin");

    Ok(global_all_users || role_requires_mfa || (global_admins && is_admin))
}

pub async fn issue_session(
    state: &AppState,
    cookies: &Cookies,
    context: &RequestContext,
    account_id: Uuid,
    remember_me: bool,
    authenticated_aal: i32,
) -> AppResult<AuthSession> {
    let session_id = Uuid::new_v4();
    let refresh_token = auth::generate_token(48);
    let csrf_token = auth::generate_token(24);
    let refresh_hash = auth::sha256_hex(&refresh_token);
    let idle_timeout =
        shared::get_global_setting_i64(&state.pool, "auth.session.idle_timeout_seconds").await?;
    let absolute_timeout =
        shared::get_global_setting_i64(&state.pool, "auth.session.absolute_timeout_seconds")
            .await?;
    let concurrent_limit =
        shared::get_global_setting_i64(&state.pool, "auth.session.concurrent_limit").await?;

    revoke_excess_sessions(&state.pool, account_id, concurrent_limit.saturating_sub(1)).await?;

    sqlx::query(
        r#"
        insert into auth.session (
            id, account_id, refresh_token_hash, authenticated_aal, remember_me, user_agent, ip_address,
            device_label, created_at, last_seen_at, idle_expires_at, absolute_expires_at
        )
        values (
            $1, $2, $3, $4, $5, $6, nullif($7, '')::inet, $8, now(), now(),
            now() + make_interval(secs => $9::integer),
            now() + make_interval(secs => $10::integer)
        )
        "#,
    )
    .bind(session_id)
    .bind(account_id)
    .bind(refresh_hash)
    .bind(authenticated_aal as i16)
    .bind(remember_me)
    .bind(context.user_agent.as_deref())
    .bind(context.ip_address.as_deref().unwrap_or_default())
    .bind(context.user_agent.as_deref().map(truncate_device_label))
    .bind(idle_timeout as i32)
    .bind(absolute_timeout as i32)
    .execute(&state.pool)
    .await?;

    auth::set_auth_cookies(cookies, &state.config, &refresh_token, &csrf_token);
    complete_session_issue(
        state,
        account_id,
        session_id,
        authenticated_aal,
        remember_me,
        context,
    )
    .await
}

async fn complete_session_issue(
    state: &AppState,
    account_id: Uuid,
    session_id: Uuid,
    authenticated_aal: i32,
    remember_me: bool,
    context: &RequestContext,
) -> AppResult<AuthSession> {
    sqlx::query(
        r#"
        update iam.account
        set last_login_at = now(),
            updated_at = now()
        where id = $1
        "#,
    )
    .bind(account_id)
    .execute(&state.pool)
    .await?;

    let (roles, scopes) = auth::load_session_roles_and_scopes(&state.pool, account_id).await?;
    let (access_token, expires_in_seconds) =
        auth::create_access_token(&state.config, account_id, session_id, roles, scopes)?;
    let user = shared::load_user_profile(&state.pool, account_id).await?;
    let device_label = context.user_agent.as_deref().map(truncate_device_label);

    shared::record_security_event(
        &state.pool,
        Some(account_id),
        "login_success",
        if authenticated_aal >= 2 {
            "low"
        } else {
            "medium"
        },
        Some("Authenticated session issued.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        device_label.as_deref(),
        json!({
            "sessionId": session_id,
            "rememberMe": remember_me,
            "aal": authenticated_aal
        }),
        Some(&context.request_id),
    )
    .await?;

    Ok(AuthSession {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in_seconds,
        user,
    })
}

async fn enqueue_email_verification(
    pool: &PgPool,
    account_id: Uuid,
    account_email_id: Uuid,
    purpose: String,
    context: &RequestContext,
) -> AppResult<()> {
    let purpose_code = match purpose.as_str() {
        "registration" => "REGISTER",
        "reverification" => "REVERIFY",
        "change_old" => "CHANGE_OLD",
        "change_new" => "CHANGE_NEW",
        _ => "REGISTER",
    };

    let verification_token = format!("verify_{}", auth::generate_token(36));
    let ttl = shared::get_global_setting_i64(pool, "auth.email.verification_ttl_seconds").await?;

    sqlx::query(
        r#"
        insert into auth.email_verification_challenge (
            id, account_email_id, purpose_code, challenge_hash, delivery_channel,
            expires_at, request_ip, request_user_agent, created_at
        )
        values (
            $1, $2, $3, $4, 'email_link',
            now() + make_interval(secs => $5::integer),
            nullif($6, '')::inet,
            $7,
            now()
        )
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(account_email_id)
    .bind(purpose_code)
    .bind(auth::sha256_hex(&verification_token))
    .bind(ttl as i32)
    .bind(context.ip_address.as_deref().unwrap_or_default())
    .bind(context.user_agent.as_deref())
    .execute(pool)
    .await?;

    shared::queue_notification(
        pool,
        Some(account_id),
        "email_verification",
        "email",
        Some("Verify your email address".to_string()),
        notification_payload(
            "email",
            "email-verification",
            json!({
                "verificationToken": verification_token,
                "accountEmailId": account_email_id,
                "purpose": purpose,
                "expiresInSeconds": ttl
            }),
        ),
    )
    .await?;

    Ok(())
}

async fn available_mfa_factors(pool: &PgPool, account_id: Uuid) -> AppResult<Vec<String>> {
    let mut factors = Vec::new();
    if sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from auth.authenticator a
            join auth.totp_factor tf on tf.authenticator_id = a.id
            where a.account_id = $1
              and a.authenticator_type = 'TOTP'
              and a.status = 'active'
              and tf.confirmed_at is not null
              and a.revoked_at is null
        )
        "#,
    )
    .bind(account_id)
    .fetch_one(pool)
    .await?
    {
        factors.push("totp".to_string());
    }

    if sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from auth.recovery_code_set rcs
            join auth.recovery_code rc on rc.recovery_code_set_id = rcs.id
            where rcs.account_id = $1
              and rcs.status = 'active'
              and rc.used_at is null
        )
        "#,
    )
    .bind(account_id)
    .fetch_one(pool)
    .await?
    {
        factors.push("recovery_code".to_string());
    }

    Ok(factors)
}

async fn verify_totp_factor(pool: &PgPool, account_id: Uuid, code: &str) -> AppResult<()> {
    let row = sqlx::query(
        r#"
        select tf.secret_ciphertext, tf.digits, tf.period_seconds
        from auth.authenticator a
        join auth.totp_factor tf on tf.authenticator_id = a.id
        where a.account_id = $1
          and a.authenticator_type = 'TOTP'
          and a.status = 'active'
          and tf.confirmed_at is not null
          and a.revoked_at is null
        limit 1
        "#,
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("TOTP is not enrolled"))?;

    let secret: Vec<u8> = row.try_get("secret_ciphertext")?;
    let digits: i16 = row.try_get("digits")?;
    let period_seconds: i16 = row.try_get("period_seconds")?;

    if auth::verify_totp_code(&secret, code, digits as u32, period_seconds as i64) {
        Ok(())
    } else {
        Err(AppError::unauthorized("verification code is invalid"))
    }
}

async fn verify_recovery_code(pool: &PgPool, account_id: Uuid, code: &str) -> AppResult<()> {
    let rows = sqlx::query(
        r#"
        select rc.id, rc.code_hash
        from auth.recovery_code_set rcs
        join auth.recovery_code rc on rc.recovery_code_set_id = rcs.id
        where rcs.account_id = $1
          and rcs.status = 'active'
          and rc.used_at is null
        order by rc.sequence_number asc
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    let hash = auth::sha256_hex(code);
    for row in rows {
        let row_hash: String = row.try_get("code_hash")?;
        if row_hash == hash {
            let recovery_code_id: Uuid = row.try_get("id")?;
            sqlx::query("update auth.recovery_code set used_at = now() where id = $1")
                .bind(recovery_code_id)
                .execute(pool)
                .await?;
            return Ok(());
        }
    }

    Err(AppError::unauthorized("recovery code is invalid"))
}

async fn enforce_lockout(
    pool: &PgPool,
    subject_type: &str,
    subject_key_hash: &str,
) -> AppResult<()> {
    let row = sqlx::query(
        r#"
        select locked_until
        from auth.account_lockout
        where subject_type = $1 and subject_key_hash = $2
        limit 1
        "#,
    )
    .bind(subject_type)
    .bind(subject_key_hash)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        let locked_until: Option<chrono::DateTime<Utc>> = row.try_get("locked_until")?;
        if locked_until
            .map(|value| value > Utc::now())
            .unwrap_or(false)
        {
            return Err(AppError::rate_limited(
                "too many failed attempts; try again later",
            ));
        }
    }

    Ok(())
}

async fn register_login_failure(
    pool: &PgPool,
    subject_type: &str,
    subject_key_hash: &str,
) -> AppResult<()> {
    let max_failures =
        shared::get_global_setting_i64(pool, "auth.rate_limit.login_max_failures").await?;
    let lockout_seconds =
        shared::get_global_setting_i64(pool, "auth.rate_limit.login_lockout_seconds").await?;

    sqlx::query(
        r#"
        insert into auth.account_lockout (
            id, subject_type, subject_key_hash, failure_count, last_failure_at, updated_at, created_at
        )
        values ($1, $2, $3, 1, now(), now(), now())
        on conflict (subject_type, subject_key_hash)
        do update
        set failure_count = auth.account_lockout.failure_count + 1,
            last_failure_at = now(),
            updated_at = now(),
            locked_until = case
                when auth.account_lockout.failure_count + 1 >= $4 then now() + make_interval(secs => $5::integer)
                else auth.account_lockout.locked_until
            end
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(subject_type)
    .bind(subject_key_hash)
    .bind(max_failures as i32)
    .bind(lockout_seconds as i32)
    .execute(pool)
    .await?;

    Ok(())
}

async fn clear_lockout_failures(
    pool: &PgPool,
    subject_type: &str,
    subject_key_hash: &str,
) -> AppResult<()> {
    sqlx::query(
        r#"
        delete from auth.account_lockout
        where subject_type = $1 and subject_key_hash = $2
        "#,
    )
    .bind(subject_type)
    .bind(subject_key_hash)
    .execute(pool)
    .await?;
    Ok(())
}

async fn revoke_excess_sessions(pool: &PgPool, account_id: Uuid, keep: i64) -> AppResult<()> {
    if keep < 0 {
        return Ok(());
    }

    sqlx::query(
        r#"
        update auth.session
        set revoked_at = now(),
            revoke_reason_code = 'concurrent_limit'
        where id in (
            select id
            from auth.session
            where account_id = $1
              and revoked_at is null
            order by created_at desc
            offset $2
        )
        "#,
    )
    .bind(account_id)
    .bind(keep)
    .execute(pool)
    .await?;

    Ok(())
}

async fn enforce_email_domain_rules(pool: &PgPool, normalized_email: &str) -> AppResult<()> {
    let domain = normalized_email
        .split('@')
        .nth(1)
        .ok_or_else(|| AppError::validation("email address is invalid"))?;

    let allowed_domains =
        shared::get_global_setting_value(pool, "security.allowed_email_domains").await?;
    let blocked_domains =
        shared::get_global_setting_value(pool, "security.blocked_email_domains").await?;

    let allowed = allowed_domains
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let blocked = blocked_domains
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if !allowed.is_empty()
        && !allowed
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(domain))
    {
        return Err(AppError::forbidden("email domain is not allowed"));
    }

    if blocked
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(domain))
    {
        return Err(AppError::forbidden("email domain is blocked"));
    }

    Ok(())
}

async fn enforce_account_access(
    pool: &PgPool,
    account_id: Uuid,
    status_code: &str,
) -> AppResult<()> {
    if status_code == "deleted" {
        return Err(AppError::forbidden("account has been deleted"));
    }
    if status_code == "pending" {
        return Err(AppError::forbidden("account is waiting for activation"));
    }

    let restriction = sqlx::query_scalar::<_, String>(
        r#"
        select restriction_type
        from iam.account_restriction
        where account_id = $1
          and status_code = 'active'
          and lifted_at is null
          and (ends_at is null or ends_at > now())
        order by created_at desc
        limit 1
        "#,
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    if let Some(restriction) = restriction {
        let message = match restriction.as_str() {
            "freeze" => "account is frozen",
            "suspend" => "account is suspended",
            "login_disabled" => "login is disabled for this account",
            _ => "account access is restricted",
        };
        return Err(AppError::forbidden(message));
    }

    Ok(())
}

fn truncate_device_label(value: &str) -> String {
    let trimmed = value.trim();
    trimmed.chars().take(120).collect()
}
