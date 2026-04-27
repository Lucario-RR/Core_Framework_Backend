use chrono::Utc;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    api::contracts::{
        AccountDeactivateRequest, Acknowledgement, AvatarUpdateRequest, EmailAddress,
        EmailAddressCreateRequest, EmailChangeRequestCreateRequest, Passkey,
        PasskeyRegistrationOptions, PasskeyRegistrationOptionsRequest,
        PasskeyRegistrationVerifyRequest, PhoneNumber, PhoneNumberCreateRequest,
        ProfileUpdateRequest, RecoveryCodeList, SecurityReportCreateRequest, Session,
        SessionBulkRevokeRequest, TotpEnableRequest, TotpSetup, UserProfile, UserSecuritySummary,
        VerificationCodeRequest,
    },
    auth::{self, AuthContext},
    error::{AppError, AppResult},
    request_context::RequestContext,
    services::shared,
    AppState,
};

pub async fn get_me(
    state: &AppState,
    auth_context: &AuthContext,
) -> AppResult<(UserProfile, String)> {
    let profile = shared::load_user_profile(&state.pool, auth_context.account_id).await?;
    let etag = current_profile_etag(&state.pool, auth_context.account_id).await?;
    Ok((profile, etag))
}

pub async fn update_me(
    state: &AppState,
    auth_context: &AuthContext,
    if_match: Option<&str>,
    request: ProfileUpdateRequest,
) -> AppResult<(UserProfile, String)> {
    enforce_if_match(&state.pool, auth_context.account_id, if_match).await?;

    sqlx::query(
        r#"
        update iam.account_profile
        set display_name = coalesce($2, display_name),
            default_currency = coalesce($3, default_currency),
            locale = coalesce($4, locale),
            timezone_name = coalesce($5, timezone_name),
            profile_bio = case when $6::text is null then profile_bio else $6 end,
            updated_at = now()
        where account_id = $1
        "#,
    )
    .bind(auth_context.account_id)
    .bind(request.display_name.map(|value| value.trim().to_string()))
    .bind(request.default_currency)
    .bind(request.locale)
    .bind(request.timezone_name)
    .bind(request.profile_bio)
    .execute(&state.pool)
    .await?;

    bump_account_revision(&state.pool, auth_context.account_id).await?;
    get_me(state, auth_context).await
}

pub async fn set_avatar(
    state: &AppState,
    auth_context: &AuthContext,
    request: AvatarUpdateRequest,
) -> AppResult<(UserProfile, String)> {
    let owns_file = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from file.file_asset
            where id = $1
              and owner_account_id = $2
              and purpose_code = 'user_avatar'
              and status = 'ready'
              and deleted_at is null
        )
        "#,
    )
    .bind(request.file_id)
    .bind(auth_context.account_id)
    .fetch_one(&state.pool)
    .await?;

    if !owns_file {
        return Err(AppError::not_found("avatar file was not found"));
    }

    sqlx::query("update iam.account_profile set avatar_file_id = $2, updated_at = now() where account_id = $1")
        .bind(auth_context.account_id)
        .bind(request.file_id)
        .execute(&state.pool)
        .await?;

    bump_account_revision(&state.pool, auth_context.account_id).await?;
    get_me(state, auth_context).await
}

pub async fn remove_avatar(
    state: &AppState,
    auth_context: &AuthContext,
) -> AppResult<(UserProfile, String)> {
    sqlx::query("update iam.account_profile set avatar_file_id = null, updated_at = now() where account_id = $1")
        .bind(auth_context.account_id)
        .execute(&state.pool)
        .await?;

    bump_account_revision(&state.pool, auth_context.account_id).await?;
    get_me(state, auth_context).await
}

pub async fn deactivate_own_account(
    state: &AppState,
    auth_context: &AuthContext,
    context: &RequestContext,
    request: AccountDeactivateRequest,
) -> AppResult<Acknowledgement> {
    verify_current_password(
        &state.pool,
        auth_context.account_id,
        &request.current_password,
    )
    .await?;

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        r#"
        insert into iam.account_restriction (
            id, account_id, restriction_type, status_code, reason_code, reason_text, starts_at, created_by_account_id, created_at
        )
        values ($1, $2, 'login_disabled', 'active', 'SELF_DEACTIVATE', $3, now(), $2, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(auth_context.account_id)
    .bind(request.reason.clone())
    .execute(&mut *tx)
    .await?;

    if request.revoke_other_sessions.unwrap_or(true) {
        sqlx::query(
            r#"
            update auth.session
            set revoked_at = now(),
                revoke_reason_code = 'self_deactivate'
            where account_id = $1
              and revoked_at is null
            "#,
        )
        .bind(auth_context.account_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    shared::record_audit_log(
        &state.pool,
        Some(auth_context.account_id),
        "account.self_deactivated",
        "account",
        Some(auth_context.account_id),
        Some("Account login disabled by the account owner.".to_string()),
        json!({"reason": request.reason}),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Account deactivated.".to_string()),
    })
}

pub async fn list_own_sessions(
    state: &AppState,
    auth_context: &AuthContext,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<Session>, Option<String>)> {
    shared::list_sessions(
        &state.pool,
        auth_context.account_id,
        Some(auth_context.session_id),
        offset,
        limit,
    )
    .await
}

pub async fn revoke_all_own_sessions(
    state: &AppState,
    auth_context: &AuthContext,
    context: &RequestContext,
    request: SessionBulkRevokeRequest,
) -> AppResult<Acknowledgement> {
    let scope = request.scope.unwrap_or_else(|| "others".to_string());
    let query = if scope == "all" {
        r#"
        update auth.session
        set revoked_at = now(),
            revoke_reason_code = 'revoke_all'
        where account_id = $1
          and revoked_at is null
        "#
    } else {
        r#"
        update auth.session
        set revoked_at = now(),
            revoke_reason_code = 'revoke_others'
        where account_id = $1
          and revoked_at is null
          and id <> $2
        "#
    };

    let mut query_builder = sqlx::query(query).bind(auth_context.account_id);
    if scope != "all" {
        query_builder = query_builder.bind(auth_context.session_id);
    }
    query_builder.execute(&state.pool).await?;

    shared::record_security_event(
        &state.pool,
        Some(auth_context.account_id),
        "session_revoked",
        "medium",
        Some("One or more sessions were revoked.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        None,
        json!({"scope": scope, "reason": request.reason}),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Sessions revoked.".to_string()),
    })
}

pub async fn revoke_own_session(
    state: &AppState,
    auth_context: &AuthContext,
    session_id: Uuid,
    context: &RequestContext,
) -> AppResult<()> {
    let affected = sqlx::query(
        r#"
        update auth.session
        set revoked_at = now(),
            revoke_reason_code = 'user_revoke'
        where id = $1
          and account_id = $2
          and revoked_at is null
        "#,
    )
    .bind(session_id)
    .bind(auth_context.account_id)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::not_found("session not found"));
    }

    shared::record_security_event(
        &state.pool,
        Some(auth_context.account_id),
        "session_revoked",
        "low",
        Some("Session revoked.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        None,
        json!({"sessionId": session_id}),
        Some(&context.request_id),
    )
    .await?;

    Ok(())
}

pub async fn get_security_summary(
    state: &AppState,
    auth_context: &AuthContext,
) -> AppResult<UserSecuritySummary> {
    shared::load_security_summary(&state.pool, auth_context.account_id).await
}

pub async fn list_own_security_events(
    state: &AppState,
    auth_context: &AuthContext,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<crate::api::contracts::SecurityEvent>, Option<String>)> {
    shared::list_security_events_for_account(&state.pool, auth_context.account_id, offset, limit)
        .await
}

pub async fn create_security_report(
    state: &AppState,
    auth_context: &AuthContext,
    context: &RequestContext,
    request: SecurityReportCreateRequest,
) -> AppResult<Acknowledgement> {
    sqlx::query(
        r#"
        insert into ops.security_report (
            id, account_id, category, description, related_event_id, status, created_at
        )
        values ($1, $2, $3, $4, $5, 'open', now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(auth_context.account_id)
    .bind(request.category)
    .bind(request.description)
    .bind(request.related_event_id)
    .execute(&state.pool)
    .await?;

    shared::record_security_event(
        &state.pool,
        Some(auth_context.account_id),
        "suspicious_login_reported",
        "high",
        Some("Suspicious account activity was reported by the account owner.".to_string()),
        context.ip_address.as_deref(),
        context.user_agent.as_deref(),
        None,
        json!({"relatedEventId": request.related_event_id}),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Security report created.".to_string()),
    })
}

pub async fn list_passkeys(
    state: &AppState,
    auth_context: &AuthContext,
) -> AppResult<Vec<Passkey>> {
    shared::list_passkeys(&state.pool, auth_context.account_id).await
}

pub async fn create_passkey_registration_options(
    state: &AppState,
    auth_context: &AuthContext,
    request: PasskeyRegistrationOptionsRequest,
) -> AppResult<PasskeyRegistrationOptions> {
    if !shared::get_global_setting_bool(&state.pool, "auth.passkey.enabled").await? {
        return Err(AppError::forbidden("passkey registration is disabled"));
    }

    let registration_id = Uuid::new_v4();
    let challenge = auth::generate_token(24);
    let user_profile = shared::load_user_profile(&state.pool, auth_context.account_id).await?;
    let public_key = json!({
        "challenge": challenge,
        "rp": {
            "name": "Core Framework Backend"
        },
        "user": {
            "id": auth_context.account_id,
            "name": user_profile.primary_email,
            "displayName": user_profile.display_name
        },
        "timeout": 60000
    });

    sqlx::query(
        r#"
        insert into auth.passkey_registration_challenge (
            id, account_id, display_name, challenge_json, expires_at, created_at
        )
        values ($1, $2, $3, $4, now() + interval '10 minutes', now())
        "#,
    )
    .bind(registration_id)
    .bind(auth_context.account_id)
    .bind(request.display_name)
    .bind(json!({ "publicKey": public_key }))
    .execute(&state.pool)
    .await?;

    Ok(PasskeyRegistrationOptions {
        registration_id,
        public_key,
    })
}

pub async fn verify_passkey_registration(
    state: &AppState,
    auth_context: &AuthContext,
    request: PasskeyRegistrationVerifyRequest,
) -> AppResult<Passkey> {
    let row = sqlx::query(
        r#"
        select id, display_name
        from auth.passkey_registration_challenge
        where id = $1
          and account_id = $2
          and verified_at is null
          and expires_at > now()
        limit 1
        "#,
    )
    .bind(request.registration_id)
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::validation("passkey registration challenge is invalid"))?;

    let registration_id: Uuid = row.try_get("id")?;
    let display_name = row
        .try_get::<Option<String>, _>("display_name")?
        .unwrap_or_else(|| "Registered passkey".to_string());
    let credential_id = request
        .credential
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::validation("credential.id is required"))?
        .to_string();

    let authenticator_id = Uuid::new_v4();
    let credential_bytes = credential_id.as_bytes().to_vec();

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        r#"
        insert into auth.authenticator (
            id, account_id, authenticator_type, usage_type, display_label, status, enrolled_at, confirmed_at, created_at
        )
        values ($1, $2, 'PASSKEY', 'PRIMARY', $3, 'active', now(), now(), now())
        "#,
    )
    .bind(authenticator_id)
    .bind(auth_context.account_id)
    .bind(&display_name)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into auth.passkey_credential (
            authenticator_id, rp_id, webauthn_user_handle, credential_id, public_key_cose, client_data_json, sign_count
        )
        values ($1, 'localhost', $2, $3, $4, $5, 0)
        "#,
    )
    .bind(authenticator_id)
    .bind(auth_context.account_id.as_bytes().to_vec())
    .bind(&credential_id)
    .bind(credential_bytes)
    .bind(request.credential)
    .execute(&mut *tx)
    .await?;

    sqlx::query("update auth.passkey_registration_challenge set verified_at = now() where id = $1")
        .bind(registration_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(Passkey {
        id: authenticator_id,
        display_name,
        created_at: Utc::now(),
        last_used_at: None,
    })
}

pub async fn delete_passkey(
    state: &AppState,
    auth_context: &AuthContext,
    passkey_id: Uuid,
) -> AppResult<()> {
    let affected = sqlx::query(
        r#"
        update auth.authenticator
        set revoked_at = now(),
            status = 'revoked'
        where id = $1
          and account_id = $2
          and authenticator_type = 'PASSKEY'
          and revoked_at is null
        "#,
    )
    .bind(passkey_id)
    .bind(auth_context.account_id)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::not_found("passkey not found"));
    }

    Ok(())
}

pub async fn create_totp_setup(
    state: &AppState,
    auth_context: &AuthContext,
) -> AppResult<TotpSetup> {
    let secret = auth::generate_totp_secret();
    let secret_base32 = auth::encode_totp_secret(&secret);
    let user_profile = shared::load_user_profile(&state.pool, auth_context.account_id).await?;
    let otpauth_uri = auth::build_otpauth_uri(
        &state.config.totp_issuer,
        &user_profile.primary_email,
        &secret_base32,
    );
    let qr_code_svg_data_url = auth::build_qr_code_svg_data_url(&otpauth_uri)?;

    let authenticator_id = Uuid::new_v4();
    sqlx::query(
        r#"
        insert into auth.authenticator (
            id, account_id, authenticator_type, usage_type, display_label, status, enrolled_at, created_at
        )
        values ($1, $2, 'TOTP', 'MFA', 'Authenticator app', 'pending', now(), now())
        "#,
    )
    .bind(authenticator_id)
    .bind(auth_context.account_id)
    .execute(&state.pool)
    .await?;

    sqlx::query(
        r#"
        insert into auth.totp_factor (
            authenticator_id, secret_ciphertext, otp_algorithm, digits, period_seconds, issuer_label
        )
        values ($1, $2, 'SHA1', 6, 30, $3)
        "#,
    )
    .bind(authenticator_id)
    .bind(secret)
    .bind(&state.config.totp_issuer)
    .execute(&state.pool)
    .await?;

    Ok(TotpSetup {
        secret: secret_base32,
        otpauth_uri,
        qr_code_svg_data_url,
    })
}

pub async fn enable_totp(
    state: &AppState,
    auth_context: &AuthContext,
    request: TotpEnableRequest,
) -> AppResult<UserSecuritySummary> {
    let row = sqlx::query(
        r#"
        select a.id as authenticator_id, tf.secret_ciphertext, tf.digits, tf.period_seconds
        from auth.authenticator a
        join auth.totp_factor tf on tf.authenticator_id = a.id
        where a.account_id = $1
          and a.authenticator_type = 'TOTP'
          and a.status = 'pending'
        order by a.created_at desc
        limit 1
        "#,
    )
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::conflict("TOTP setup has not been started"))?;

    let authenticator_id: Uuid = row.try_get("authenticator_id")?;
    let secret: Vec<u8> = row.try_get("secret_ciphertext")?;
    let digits: i16 = row.try_get("digits")?;
    let period_seconds: i16 = row.try_get("period_seconds")?;

    if !auth::verify_totp_code(&secret, &request.code, digits as u32, period_seconds as i64) {
        return Err(AppError::unauthorized("verification code is invalid"));
    }

    sqlx::query(
        r#"
        update auth.authenticator
        set status = 'active',
            confirmed_at = now()
        where id = $1
        "#,
    )
    .bind(authenticator_id)
    .execute(&state.pool)
    .await?;

    sqlx::query("update auth.totp_factor set confirmed_at = now() where authenticator_id = $1")
        .bind(authenticator_id)
        .execute(&state.pool)
        .await?;

    rotate_recovery_codes(state, auth_context).await?;
    shared::load_security_summary(&state.pool, auth_context.account_id).await
}

pub async fn disable_totp(
    state: &AppState,
    auth_context: &AuthContext,
    request: VerificationCodeRequest,
) -> AppResult<UserSecuritySummary> {
    let row = sqlx::query(
        r#"
        select a.id as authenticator_id, tf.secret_ciphertext, tf.digits, tf.period_seconds
        from auth.authenticator a
        join auth.totp_factor tf on tf.authenticator_id = a.id
        where a.account_id = $1
          and a.authenticator_type = 'TOTP'
          and a.status = 'active'
          and a.revoked_at is null
        limit 1
        "#,
    )
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::conflict("TOTP is not enabled"))?;

    let authenticator_id: Uuid = row.try_get("authenticator_id")?;
    let secret: Vec<u8> = row.try_get("secret_ciphertext")?;
    let digits: i16 = row.try_get("digits")?;
    let period_seconds: i16 = row.try_get("period_seconds")?;

    if !auth::verify_totp_code(&secret, &request.code, digits as u32, period_seconds as i64) {
        return Err(AppError::unauthorized("verification code is invalid"));
    }

    sqlx::query(
        r#"
        update auth.authenticator
        set status = 'revoked',
            revoked_at = now()
        where id = $1
        "#,
    )
    .bind(authenticator_id)
    .execute(&state.pool)
    .await?;

    shared::load_security_summary(&state.pool, auth_context.account_id).await
}

pub async fn rotate_recovery_codes(
    state: &AppState,
    auth_context: &AuthContext,
) -> AppResult<RecoveryCodeList> {
    let codes = auth::generate_recovery_codes(10);
    let new_set_id = Uuid::new_v4();
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        r#"
        insert into auth.recovery_code_set (id, account_id, code_count, status, issued_at)
        values ($1, $2, $3, 'active', now())
        "#,
    )
    .bind(new_set_id)
    .bind(auth_context.account_id)
    .bind(codes.len() as i16)
    .execute(&mut *tx)
    .await?;

    for (index, code) in codes.iter().enumerate() {
        sqlx::query(
            r#"
            insert into auth.recovery_code (
                id, recovery_code_set_id, sequence_number, code_hash, salt_value, hash_algorithm, created_at
            )
            values ($1, $2, $3, $4, $5, 'SHA256', now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(new_set_id)
        .bind(index as i16 + 1)
        .bind(auth::sha256_hex(code))
        .bind(Vec::<u8>::new())
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        r#"
        update auth.recovery_code_set
        set status = 'replaced',
            replaced_by_set_id = $2
        where account_id = $1
          and status = 'active'
          and id <> $2
        "#,
    )
    .bind(auth_context.account_id)
    .bind(new_set_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(RecoveryCodeList { codes })
}

pub async fn list_emails(
    state: &AppState,
    auth_context: &AuthContext,
) -> AppResult<Vec<EmailAddress>> {
    shared::load_email_addresses(&state.pool, auth_context.account_id).await
}

pub async fn create_email(
    state: &AppState,
    auth_context: &AuthContext,
    context: &RequestContext,
    request: EmailAddressCreateRequest,
) -> AppResult<EmailAddress> {
    let email_id = Uuid::new_v4();
    let normalized = crate::utils::normalize_email(&request.email);

    let exists = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1 from iam.account_email where normalized_email = $1 and deleted_at is null
        )
        "#,
    )
    .bind(&normalized)
    .fetch_one(&state.pool)
    .await?;
    if exists {
        return Err(AppError::conflict("email already exists"));
    }

    sqlx::query(
        r#"
        insert into iam.account_email (
            id, account_id, email, normalized_email, label, is_login_enabled, is_primary_for_account, verification_status, created_at, updated_at
        )
        values ($1, $2, $3, $4, $5, false, false, 'pending', now(), now())
        "#,
    )
    .bind(email_id)
    .bind(auth_context.account_id)
    .bind(request.email.trim())
    .bind(&normalized)
    .bind(request.label.trim())
    .execute(&state.pool)
    .await?;

    enqueue_email_code(&state.pool, auth_context.account_id, email_id, context).await?;
    get_email_by_id(&state.pool, auth_context.account_id, email_id).await
}

pub async fn delete_email(
    state: &AppState,
    auth_context: &AuthContext,
    email_id: Uuid,
) -> AppResult<()> {
    let is_primary = sqlx::query_scalar::<_, bool>(
        r#"
        select coalesce(is_primary_for_account, false)
        from iam.account_email
        where id = $1 and account_id = $2 and deleted_at is null
        "#,
    )
    .bind(email_id)
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("email not found"))?;

    if is_primary {
        return Err(AppError::validation("primary email cannot be deleted"));
    }

    sqlx::query("update iam.account_email set deleted_at = now(), updated_at = now() where id = $1 and account_id = $2")
        .bind(email_id)
        .bind(auth_context.account_id)
        .execute(&state.pool)
        .await?;
    Ok(())
}

pub async fn verify_email(
    state: &AppState,
    auth_context: &AuthContext,
    email_id: Uuid,
    request: VerificationCodeRequest,
) -> AppResult<EmailAddress> {
    let code_hash = auth::sha256_hex(&request.code);
    let challenge = sqlx::query_scalar::<_, Uuid>(
        r#"
        select id
        from auth.email_verification_challenge
        where account_email_id = $1
          and challenge_hash = $2
          and delivery_channel = 'email_otp'
          and consumed_at is null
          and invalidated_at is null
          and expires_at > now()
        order by created_at desc
        limit 1
        "#,
    )
    .bind(email_id)
    .bind(code_hash)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("verification code is invalid"))?;

    sqlx::query("update auth.email_verification_challenge set consumed_at = now() where id = $1")
        .bind(challenge)
        .execute(&state.pool)
        .await?;
    sqlx::query(
        r#"
        update iam.account_email
        set verification_status = 'verified',
            verified_at = now(),
            updated_at = now()
        where id = $1 and account_id = $2
        "#,
    )
    .bind(email_id)
    .bind(auth_context.account_id)
    .execute(&state.pool)
    .await?;

    get_email_by_id(&state.pool, auth_context.account_id, email_id).await
}

pub async fn make_email_primary(
    state: &AppState,
    auth_context: &AuthContext,
    email_id: Uuid,
) -> AppResult<EmailAddress> {
    let verified = sqlx::query_scalar::<_, bool>(
        r#"
        select verification_status = 'verified'
        from iam.account_email
        where id = $1 and account_id = $2 and deleted_at is null
        "#,
    )
    .bind(email_id)
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("email not found"))?;

    if !verified {
        return Err(AppError::conflict(
            "email must be verified before it can become primary",
        ));
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query("update iam.account_email set is_primary_for_account = false, updated_at = now() where account_id = $1 and deleted_at is null")
        .bind(auth_context.account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"
        update iam.account_email
        set is_primary_for_account = true,
            is_login_enabled = true,
            updated_at = now()
        where id = $1 and account_id = $2
        "#,
    )
    .bind(email_id)
    .bind(auth_context.account_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    get_email_by_id(&state.pool, auth_context.account_id, email_id).await
}

pub async fn resend_email_verification(
    state: &AppState,
    auth_context: &AuthContext,
    context: &RequestContext,
    email_id: Uuid,
) -> AppResult<Acknowledgement> {
    ensure_email_ownership(&state.pool, auth_context.account_id, email_id).await?;
    enqueue_email_code(&state.pool, auth_context.account_id, email_id, context).await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Verification challenge accepted for delivery.".to_string()),
    })
}

pub async fn create_email_change_request(
    state: &AppState,
    auth_context: &AuthContext,
    context: &RequestContext,
    request: EmailChangeRequestCreateRequest,
) -> AppResult<Acknowledgement> {
    let old_primary = sqlx::query(
        r#"
        select id
        from iam.account_email
        where account_id = $1
          and is_primary_for_account = true
          and deleted_at is null
        limit 1
        "#,
    )
    .bind(auth_context.account_id)
    .fetch_one(&state.pool)
    .await?;
    let old_email_id: Uuid = old_primary.try_get("id")?;

    let new_email_id = Uuid::new_v4();
    let normalized = crate::utils::normalize_email(&request.new_email);
    let change_id = Uuid::new_v4();

    let exists = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from iam.account_email
            where normalized_email = $1
              and deleted_at is null
        )
        "#,
    )
    .bind(&normalized)
    .fetch_one(&state.pool)
    .await?;
    if exists {
        return Err(AppError::conflict("email already exists"));
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        r#"
        insert into iam.account_email (
            id, account_id, email, normalized_email, label, is_login_enabled, is_primary_for_account, verification_status, created_at, updated_at
        )
        values ($1, $2, $3, $4, 'other', true, false, 'pending', now(), now())
        on conflict do nothing
        "#,
    )
    .bind(new_email_id)
    .bind(auth_context.account_id)
    .bind(request.new_email.trim())
    .bind(&normalized)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into auth.account_email_change_request (
            id, account_id, old_account_email_id, new_email, new_normalized_email, status, expires_at, created_at
        )
        values ($1, $2, $3, $4, $5, 'pending', now() + interval '1 day', now())
        "#,
    )
    .bind(change_id)
    .bind(auth_context.account_id)
    .bind(old_email_id)
    .bind(request.new_email.trim())
    .bind(&normalized)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    enqueue_email_link_with_purpose(
        &state.pool,
        auth_context.account_id,
        old_email_id,
        "change_old",
        context,
    )
    .await?;
    enqueue_email_link_with_purpose(
        &state.pool,
        auth_context.account_id,
        new_email_id,
        "change_new",
        context,
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Email change flow started.".to_string()),
    })
}

pub async fn list_phones(
    state: &AppState,
    auth_context: &AuthContext,
) -> AppResult<Vec<PhoneNumber>> {
    shared::load_phone_numbers(&state.pool, auth_context.account_id).await
}

pub async fn create_phone(
    state: &AppState,
    auth_context: &AuthContext,
    context: &RequestContext,
    request: PhoneNumberCreateRequest,
) -> AppResult<PhoneNumber> {
    let phone_id = Uuid::new_v4();
    sqlx::query(
        r#"
        insert into iam.account_phone (
            id, account_id, e164_phone_number, label, is_sms_enabled, is_primary_for_account, verification_status, created_at, updated_at
        )
        values ($1, $2, $3, $4, false, false, 'pending', now(), now())
        "#,
    )
    .bind(phone_id)
    .bind(auth_context.account_id)
    .bind(request.phone_number.trim())
    .bind(request.label.trim())
    .execute(&state.pool)
    .await?;

    enqueue_phone_code(&state.pool, auth_context.account_id, phone_id, context).await?;
    get_phone_by_id(&state.pool, auth_context.account_id, phone_id).await
}

pub async fn delete_phone(
    state: &AppState,
    auth_context: &AuthContext,
    phone_id: Uuid,
) -> AppResult<()> {
    let affected = sqlx::query(
        r#"
        update iam.account_phone
        set deleted_at = now(),
            updated_at = now()
        where id = $1 and account_id = $2 and deleted_at is null
        "#,
    )
    .bind(phone_id)
    .bind(auth_context.account_id)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::not_found("phone not found"));
    }

    Ok(())
}

pub async fn verify_phone(
    state: &AppState,
    auth_context: &AuthContext,
    phone_id: Uuid,
    request: VerificationCodeRequest,
) -> AppResult<PhoneNumber> {
    let code_hash = auth::sha256_hex(&request.code);
    let challenge_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        select pvc.id
        from auth.phone_verification_challenge pvc
        join iam.account_phone ap on ap.id = pvc.account_phone_id
        where pvc.account_phone_id = $1
          and pvc.challenge_hash = $2
          and pvc.consumed_at is null
          and pvc.invalidated_at is null
          and pvc.expires_at > now()
          and ap.account_id = $3
        order by pvc.created_at desc
        limit 1
        "#,
    )
    .bind(phone_id)
    .bind(code_hash)
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::unauthorized("verification code is invalid"))?;

    sqlx::query("update auth.phone_verification_challenge set consumed_at = now() where id = $1")
        .bind(challenge_id)
        .execute(&state.pool)
        .await?;
    sqlx::query(
        r#"
        update iam.account_phone
        set verification_status = 'verified',
            verified_at = now(),
            updated_at = now()
        where id = $1 and account_id = $2
        "#,
    )
    .bind(phone_id)
    .bind(auth_context.account_id)
    .execute(&state.pool)
    .await?;

    get_phone_by_id(&state.pool, auth_context.account_id, phone_id).await
}

pub async fn make_phone_primary(
    state: &AppState,
    auth_context: &AuthContext,
    phone_id: Uuid,
) -> AppResult<PhoneNumber> {
    let verified = sqlx::query_scalar::<_, bool>(
        r#"
        select verification_status = 'verified'
        from iam.account_phone
        where id = $1 and account_id = $2 and deleted_at is null
        "#,
    )
    .bind(phone_id)
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("phone not found"))?;

    if !verified {
        return Err(AppError::conflict(
            "phone must be verified before it can become primary",
        ));
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query("update iam.account_phone set is_primary_for_account = false, updated_at = now() where account_id = $1 and deleted_at is null")
        .bind(auth_context.account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"
        update iam.account_phone
        set is_primary_for_account = true,
            is_login_enabled = true,
            updated_at = now()
        where id = $1 and account_id = $2
        "#,
    )
    .bind(phone_id)
    .bind(auth_context.account_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    get_phone_by_id(&state.pool, auth_context.account_id, phone_id).await
}

async fn current_profile_etag(pool: &sqlx::PgPool, account_id: Uuid) -> AppResult<String> {
    let revision =
        sqlx::query_scalar::<_, i64>("select row_version from iam.account where id = $1")
            .bind(account_id)
            .fetch_one(pool)
            .await?;
    Ok(format!("W/\"rev-{revision}\""))
}

async fn enforce_if_match(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    if_match: Option<&str>,
) -> AppResult<()> {
    if let Some(if_match) = if_match {
        let current = current_profile_etag(pool, account_id).await?;
        if current != if_match {
            return Err(AppError::precondition_failed("resource has been modified"));
        }
    }
    Ok(())
}

async fn bump_account_revision(pool: &sqlx::PgPool, account_id: Uuid) -> AppResult<()> {
    sqlx::query(
        r#"
        update iam.account
        set row_version = row_version + 1,
            updated_at = now()
        where id = $1
        "#,
    )
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn verify_current_password(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    password: &str,
) -> AppResult<()> {
    let hash = sqlx::query_scalar::<_, String>(
        r#"
        select pc.password_hash
        from auth.authenticator au
        join auth.password_credential pc on pc.authenticator_id = au.id
        where au.account_id = $1
          and au.authenticator_type = 'PASSWORD'
          and au.revoked_at is null
        limit 1
        "#,
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::conflict("password credential is not available"))?;

    if auth::verify_password(password, &hash)? {
        Ok(())
    } else {
        Err(AppError::unauthorized("current password is invalid"))
    }
}

async fn get_email_by_id(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    email_id: Uuid,
) -> AppResult<EmailAddress> {
    let emails = shared::load_email_addresses(pool, account_id).await?;
    emails
        .into_iter()
        .find(|email| email.id == email_id)
        .ok_or_else(|| AppError::not_found("email not found"))
}

async fn ensure_email_ownership(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    email_id: Uuid,
) -> AppResult<()> {
    let exists = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from iam.account_email
            where id = $1 and account_id = $2 and deleted_at is null
        )
        "#,
    )
    .bind(email_id)
    .bind(account_id)
    .fetch_one(pool)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(AppError::not_found("email not found"))
    }
}

async fn enqueue_email_code(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    email_id: Uuid,
    context: &RequestContext,
) -> AppResult<()> {
    let code = auth::generate_numeric_code(6);
    sqlx::query(
        r#"
        insert into auth.email_verification_challenge (
            id, account_email_id, purpose_code, challenge_hash, delivery_channel, expires_at, request_ip, request_user_agent, created_at
        )
        values ($1, $2, 'VERIFY_EMAIL', $3, 'email_otp', now() + interval '15 minutes', nullif($4, '')::inet, $5, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(email_id)
    .bind(auth::sha256_hex(&code))
    .bind(context.ip_address.as_deref().unwrap_or_default())
    .bind(context.user_agent.as_deref())
    .execute(pool)
    .await?;

    shared::queue_notification(
        pool,
        Some(account_id),
        "secondary_email_verification",
        "email",
        Some("Verify your email code".to_string()),
        auth::notification_payload(
            "email",
            "secondary-email-verification",
            json!({"code": code, "emailId": email_id}),
        ),
    )
    .await?;

    Ok(())
}

async fn enqueue_email_link_with_purpose(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    email_id: Uuid,
    purpose: &str,
    context: &RequestContext,
) -> AppResult<()> {
    let token = format!("verify_{}", auth::generate_token(36));
    let purpose_code = match purpose {
        "change_old" => "CHANGE_OLD",
        "change_new" => "CHANGE_NEW",
        _ => "REGISTER",
    };

    sqlx::query(
        r#"
        insert into auth.email_verification_challenge (
            id, account_email_id, purpose_code, challenge_hash, delivery_channel, expires_at, request_ip, request_user_agent, created_at
        )
        values ($1, $2, $3, $4, 'email_link', now() + interval '1 day', nullif($5, '')::inet, $6, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(email_id)
    .bind(purpose_code)
    .bind(auth::sha256_hex(&token))
    .bind(context.ip_address.as_deref().unwrap_or_default())
    .bind(context.user_agent.as_deref())
    .execute(pool)
    .await?;

    shared::queue_notification(
        pool,
        Some(account_id),
        "email_change_verification",
        "email",
        Some("Confirm email change".to_string()),
        auth::notification_payload(
            "email",
            "email-change",
            json!({"verificationToken": token, "purpose": purpose, "emailId": email_id}),
        ),
    )
    .await?;

    Ok(())
}

async fn get_phone_by_id(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    phone_id: Uuid,
) -> AppResult<PhoneNumber> {
    let phones = shared::load_phone_numbers(pool, account_id).await?;
    phones
        .into_iter()
        .find(|phone| phone.id == phone_id)
        .ok_or_else(|| AppError::not_found("phone not found"))
}

async fn enqueue_phone_code(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    phone_id: Uuid,
    context: &RequestContext,
) -> AppResult<()> {
    let code = auth::generate_numeric_code(6);
    sqlx::query(
        r#"
        insert into auth.phone_verification_challenge (
            id, account_phone_id, challenge_hash, expires_at, request_ip, request_user_agent, created_at
        )
        values ($1, $2, $3, now() + interval '15 minutes', nullif($4, '')::inet, $5, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(phone_id)
    .bind(auth::sha256_hex(&code))
    .bind(context.ip_address.as_deref().unwrap_or_default())
    .bind(context.user_agent.as_deref())
    .execute(pool)
    .await?;

    shared::queue_notification(
        pool,
        Some(account_id),
        "phone_verification",
        "sms",
        Some("Verify your phone".to_string()),
        auth::notification_payload(
            "sms",
            "phone-verification",
            json!({"code": code, "phoneId": phone_id}),
        ),
    )
    .await?;

    Ok(())
}
