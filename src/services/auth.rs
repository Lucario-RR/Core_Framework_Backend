use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::{
    api::contracts::{
        Acknowledgement, AuthSession, EmailVerificationConfirmRequest, EmailVerificationResendRequest, LoginRequest,
        MfaChallenge, MfaVerifyRequest, PasskeyAuthenticationOptions, PasskeyAuthenticationOptionsRequest,
        PasskeyAuthenticationVerifyRequest, PasswordChangeRequest, PasswordForgotRequest, PasswordResetRequest,
        RegisterRequest,
    },
    auth::{self, notification_payload, AuthContext},
    error::{AppError, AppResult},
    request_context::RequestContext,
    services::shared,
    utils::normalize_email,
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

pub async fn register(
    state: &AppState,
    cookies: &Cookies,
    context: &RequestContext,
    request: RegisterRequest,
) -> AppResult<AuthSession> {
    if !shared::get_global_setting_bool(&state.pool, "registration.enabled").await? {
        return Err(AppError::forbidden("public registration is currently disabled"));
    }

    if shared::get_global_setting_bool(&state.pool, "registration.invite_only").await? {
        return Err(AppError::forbidden(
            "invite-only registration is enabled and this endpoint requires an invite flow",
        ));
    }

    let created = create_local_account(
        &state.pool,
        context,
        request,
        vec!["user".to_string()],
        None,
        Some("active".to_string()),
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
        || !shared::get_global_setting_bool(&state.pool, "registration.bootstrap_admin_enabled").await?
    {
        return Err(AppError::forbidden("bootstrap admin registration is disabled"));
    }

    let existing_admins = sqlx::query_scalar::<_, i64>(
        r#"
        select count(distinct ar.account_id)
        from iam.account_role ar
        join iam.role r on r.id = ar.role_id
        where r.code = 'admin'
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    if existing_admins > 0 {
        return Err(AppError::conflict("an administrator account already exists"));
    }

    let created = create_local_account(
        &state.pool,
        context,
        request,
        vec!["admin".to_string()],
        None,
        Some("active".to_string()),
        false,
    )
    .await?;

    issue_session(state, cookies, context, created.account_id, false, 2).await
}

pub async fn login(
    state: &AppState,
    cookies: &Cookies,
    context: &RequestContext,
    request: LoginRequest,
) -> AppResult<LoginOutcome> {
    let normalized_email = normalize_email(&request.email);
    let subject_hash = auth::sha256_hex(&normalized_email);
    enforce_lockout(&state.pool, "email", &subject_hash).await?;

    let row = sqlx::query(
        r#"
        select
            a.id as account_id,
            a.status_code,
            ae.id as email_id,
            ae.verification_status,
            pc.password_hash,
            pc.password_version,
            pc.must_rotate
        from iam.account_email ae
        join iam.account a on a.id = ae.account_id
        join auth.authenticator au on au.account_id = a.id and au.authenticator_type = 'PASSWORD' and au.revoked_at is null
        join auth.password_credential pc on pc.authenticator_id = au.id
        where ae.normalized_email = $1
          and ae.deleted_at is null
          and ae.is_login_enabled = true
        limit 1
        "#,
    )
    .bind(&normalized_email)
    .fetch_optional(&state.pool)
    .await?;

    let Some(row) = row else {
        register_login_failure(&state.pool, "email", &subject_hash).await?;
        return Err(AppError::unauthorized("email or password is invalid"));
    };

    let account_id: Uuid = row.try_get("account_id")?;
    let password_hash: String = row.try_get("password_hash")?;
    let status_code: String = row.try_get("status_code")?;

    enforce_account_access(&state.pool, account_id, &status_code).await?;

    if !auth::verify_password(&request.password, &password_hash)? {
        register_login_failure(&state.pool, "email", &subject_hash).await?;
        shared::record_security_event(
            &state.pool,
            Some(account_id),
            "login_failure",
            "medium",
            Some("Invalid password supplied.".to_string()),
            context.ip_address.as_deref(),
            context.user_agent.as_deref(),
            None,
            json!({"normalizedEmail": normalized_email}),
            Some(&context.request_id),
        )
        .await?;
        return Err(AppError::unauthorized("email or password is invalid"));
    }

    clear_lockout_failures(&state.pool, "email", &subject_hash).await?;

    let security = shared::load_security_summary(&state.pool, account_id).await?;
    if security.mfa_enabled || security.mfa_required {
        let available_factors = available_mfa_factors(&state.pool, account_id).await?;
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

    let idle_timeout = shared::get_global_setting_i64(&state.pool, "auth.session.idle_timeout_seconds").await?;
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
    complete_session_issue(state, account_id, session_id, aal as i32, remember_me, context).await
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
    let minimum_length = shared::get_global_setting_i64(&state.pool, "auth.password.min_length").await?;
    if request.new_password.len() < minimum_length as usize {
        return Err(AppError::validation(format!(
            "newPassword must be at least {minimum_length} characters"
        )));
    }

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
        return Err(AppError::conflict("new password must differ from the current password"));
    }

    let history_limit = shared::get_global_setting_i64(&state.pool, "auth.password.history_count").await?;
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
        return Err(AppError::conflict("new password cannot reuse a recent password"));
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
        let ttl = shared::get_global_setting_i64(&state.pool, "auth.password.reset_ttl_seconds").await?;

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
    let minimum_length = shared::get_global_setting_i64(&state.pool, "auth.password.min_length").await?;
    if request.new_password.len() < minimum_length as usize {
        return Err(AppError::validation(format!(
            "newPassword must be at least {minimum_length} characters"
        )));
    }

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
            request.purpose.unwrap_or_else(|| "registration".to_string()),
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
        _ => return Err(AppError::validation("factorType must be totp or recovery_code")),
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
            return Err(AppError::unauthorized("passkey credential is not registered"));
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

    sqlx::query("update auth.passkey_authentication_challenge set verified_at = now() where id = $1")
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
    require_password_change: bool,
) -> AppResult<CreatedAccount> {
    if created_by_account_id.is_none() && request.accepted_legal_documents.is_empty() {
        return Err(AppError::validation("acceptedLegalDocuments must contain at least one document"));
    }

    let password_min_length = shared::get_global_setting_i64(pool, "auth.password.min_length").await?;
    if request.password.len() < password_min_length as usize {
        return Err(AppError::validation(format!(
            "password must be at least {password_min_length} characters"
        )));
    }

    let account_id = Uuid::new_v4();
    let primary_email_id = Uuid::new_v4();
    let normalized_email = normalize_email(&request.email);
    let normalized_phone = request.primary_phone.as_ref().map(|value| value.trim().to_string());

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
        return Err(AppError::conflict("an account already exists for that email address"));
    }

    enforce_email_domain_rules(pool, &normalized_email).await?;

    let password = auth::hash_password(&request.password)?;
    let password_authenticator_id = Uuid::new_v4();
    let now = Utc::now();
    let status_code = requested_status.unwrap_or_else(|| "active".to_string());

    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        insert into iam.account (id, status_code, created_by_account_id, activated_at, created_at, updated_at)
        values ($1, $2, $3, case when $2 = 'active' then now() else null end, now(), now())
        "#,
    )
    .bind(account_id)
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
                verification_status, created_at, updated_at
            )
            values ($1, $2, $3, 'primary', false, true, 'pending', now(), now())
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
            on conflict do nothing
            "#,
        )
        .bind(account_id)
        .bind(created_by_account_id)
        .bind(role_code)
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

    enqueue_email_verification(pool, account_id, primary_email_id, "registration".to_string(), context).await?;
    shared::record_audit_log(
        pool,
        created_by_account_id,
        "account.created",
        "account",
        Some(account_id),
        Some("Account created.".to_string()),
        json!({ "bootstrap": created_by_account_id.is_none() }),
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
    let idle_timeout = shared::get_global_setting_i64(&state.pool, "auth.session.idle_timeout_seconds").await?;
    let absolute_timeout = shared::get_global_setting_i64(&state.pool, "auth.session.absolute_timeout_seconds").await?;
    let concurrent_limit = shared::get_global_setting_i64(&state.pool, "auth.session.concurrent_limit").await?;

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
    complete_session_issue(state, account_id, session_id, authenticated_aal, remember_me, context).await
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

    shared::record_security_event(
        &state.pool,
        Some(account_id),
        "login_success",
        if authenticated_aal >= 2 { "low" } else { "medium" },
        Some("Authenticated session issued.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        context.user_agent.as_deref().map(truncate_device_label),
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

async fn enforce_lockout(pool: &PgPool, subject_type: &str, subject_key_hash: &str) -> AppResult<()> {
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
        if locked_until.map(|value| value > Utc::now()).unwrap_or(false) {
            return Err(AppError::rate_limited("too many failed attempts; try again later"));
        }
    }

    Ok(())
}

async fn register_login_failure(pool: &PgPool, subject_type: &str, subject_key_hash: &str) -> AppResult<()> {
    let max_failures = shared::get_global_setting_i64(pool, "auth.rate_limit.login_max_failures").await?;
    let lockout_seconds = shared::get_global_setting_i64(pool, "auth.rate_limit.login_lockout_seconds").await?;

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

async fn clear_lockout_failures(pool: &PgPool, subject_type: &str, subject_key_hash: &str) -> AppResult<()> {
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

    let allowed_domains = shared::get_global_setting_value(pool, "security.allowed_email_domains").await?;
    let blocked_domains = shared::get_global_setting_value(pool, "security.blocked_email_domains").await?;

    let allowed = allowed_domains
        .as_array()
        .map(|values| values.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    let blocked = blocked_domains
        .as_array()
        .map(|values| values.iter().filter_map(|value| value.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    if !allowed.is_empty() && !allowed.iter().any(|candidate| candidate.eq_ignore_ascii_case(domain)) {
        return Err(AppError::forbidden("email domain is not allowed"));
    }

    if blocked.iter().any(|candidate| candidate.eq_ignore_ascii_case(domain)) {
        return Err(AppError::forbidden("email domain is blocked"));
    }

    Ok(())
}

async fn enforce_account_access(pool: &PgPool, account_id: Uuid, status_code: &str) -> AppResult<()> {
    if status_code == "deleted" {
        return Err(AppError::forbidden("account has been deleted"));
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
