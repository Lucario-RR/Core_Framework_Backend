use chrono::Utc;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    api::contracts::{
        Acknowledgement, AdminOverview, AdminSystemSetting, AdminSystemSettingUpdateRequest, AdminUserBulkActionRequest,
        AdminUserCreateRequest, AdminUserSummary, AdminUserUpdateRequest, EmailAddress, RegisterRequest, RoleDefinition,
        SessionBulkRevokeRequest,
    },
    auth::AuthContext,
    error::{AppError, AppResult},
    request_context::RequestContext,
    services::{auth as auth_service, shared},
    AppState,
};

pub async fn list_roles(state: &AppState) -> AppResult<Vec<RoleDefinition>> {
    shared::list_roles(&state.pool).await
}

pub async fn admin_overview(state: &AppState) -> AppResult<AdminOverview> {
    shared::count_admin_overview(&state.pool, state.config.public_admin_bootstrap_enabled).await
}

pub async fn list_audit_logs(
    state: &AppState,
    search: Option<&str>,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<crate::api::contracts::AuditLogEntry>, Option<String>)> {
    shared::list_audit_logs(&state.pool, search, None, offset, limit).await
}

pub async fn list_security_events(
    state: &AppState,
    search: Option<&str>,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<crate::api::contracts::AdminSecurityEvent>, Option<String>)> {
    shared::list_security_events_admin(&state.pool, search, None, offset, limit).await
}

pub async fn list_admin_users(
    state: &AppState,
    search: Option<&str>,
    status: Option<&str>,
    role: Option<&str>,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<AdminUserSummary>, Option<String>)> {
    let search_value = search.map(|value| format!("%{}%", value.trim().to_ascii_lowercase()));
    let role_code = role.map(|value| value.to_ascii_lowercase());

    let account_ids = sqlx::query_scalar::<_, Uuid>(
        r#"
        select distinct a.id
        from iam.account a
        join iam.account_profile p on p.account_id = a.id
        left join iam.account_email ae on ae.account_id = a.id and ae.is_primary_for_account = true and ae.deleted_at is null
        left join iam.account_role ar on ar.account_id = a.id
        left join iam.role r on r.id = ar.role_id
        where ($1::text is null
               or lower(coalesce(p.display_name, '')) ilike $1
               or lower(coalesce(ae.email, '')) ilike $1
               or cast(a.id as text) ilike $1)
          and ($2::text is null or r.code = $2)
        order by a.created_at desc
        limit 500
        "#,
    )
    .bind(search_value)
    .bind(role_code)
    .fetch_all(&state.pool)
    .await?;

    let mut summaries = Vec::new();
    for account_id in account_ids {
        let summary = shared::load_admin_user_summary(&state.pool, account_id).await?;
        if status.map(|expected| expected == summary.status).unwrap_or(true) {
            summaries.push(summary);
        }
    }

    let total = summaries.len() as i64;
    let next_cursor = (offset + limit < total).then(|| crate::utils::encode_offset_cursor(offset + limit));
    let items = summaries
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    Ok((items, next_cursor))
}

pub async fn create_admin_user(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    request: AdminUserCreateRequest,
) -> AppResult<AdminUserSummary> {
    let requested_status = request.account_status.clone();
    let register_request = RegisterRequest {
        email: request.email,
        password: request.password,
        display_name: request.display_name,
        primary_phone: request.primary_phone,
        accepted_legal_documents: Vec::new(),
    };
    let role_codes = request.role_codes.unwrap_or_else(|| vec!["user".to_string()]);
    let initial_status = match requested_status.as_deref() {
        Some("pending") => Some("pending".to_string()),
        _ => Some("active".to_string()),
    };
    let created = auth_service::create_local_account(
        &state.pool,
        context,
        register_request,
        role_codes,
        Some(actor.account_id),
        initial_status,
        false,
    )
    .await?;

    if let Some(status) = requested_status.as_deref() {
        if status != "active" && status != "pending" {
            let mut tx = state.pool.begin().await?;
            apply_account_status(&mut tx, created.account_id, actor.account_id, status, Some("Initial admin-created status".to_string())).await?;
            tx.commit().await?;
        }
    }

    shared::load_admin_user_summary(&state.pool, created.account_id).await
}

pub async fn get_admin_user(state: &AppState, account_id: Uuid) -> AppResult<AdminUserSummary> {
    shared::load_admin_user_summary(&state.pool, account_id).await
}

pub async fn update_admin_user(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    account_id: Uuid,
    request: AdminUserUpdateRequest,
) -> AppResult<AdminUserSummary> {
    let mut tx = state.pool.begin().await?;

    if request.display_name.is_some()
        || request.default_currency.is_some()
        || request.locale.is_some()
        || request.timezone_name.is_some()
        || request.profile_bio.is_some()
    {
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
        .bind(account_id)
        .bind(request.display_name.map(|value| value.trim().to_string()))
        .bind(request.default_currency)
        .bind(request.locale)
        .bind(request.timezone_name)
        .bind(request.profile_bio)
        .execute(&mut *tx)
        .await?;
    }

    if let Some(primary_email) = request.primary_email.as_ref() {
        upsert_admin_primary_email(&mut tx, account_id, primary_email).await?;
    }

    if let Some(primary_phone) = request.primary_phone.as_ref() {
        upsert_admin_primary_phone(&mut tx, account_id, primary_phone).await?;
    }

    if let Some(role_codes) = request.role_codes.as_ref() {
        sqlx::query("delete from iam.account_role where account_id = $1")
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        for role_code in role_codes {
            sqlx::query(
                r#"
                insert into iam.account_role (account_id, role_id, granted_by_account_id, granted_at)
                select $1, id, $2, now()
                from iam.role
                where code = $3
                "#,
            )
            .bind(account_id)
            .bind(actor.account_id)
            .bind(role_code)
            .execute(&mut *tx)
            .await?;
        }
    }

    if let Some(require_password_change) = request.require_password_change {
        sqlx::query(
            r#"
            update auth.password_credential
            set must_rotate = $2
            where authenticator_id in (
                select id
                from auth.authenticator
                where account_id = $1
                  and authenticator_type = 'PASSWORD'
                  and revoked_at is null
            )
            "#,
        )
        .bind(account_id)
        .bind(require_password_change)
        .execute(&mut *tx)
        .await?;
    }

    if let Some(require_mfa_enrollment) = request.require_mfa_enrollment {
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
        .bind(json!(require_mfa_enrollment))
        .execute(&mut *tx)
        .await?;
    }

    if let Some(disable_login) = request.disable_login {
        set_login_disabled(&mut tx, account_id, actor.account_id, disable_login, request.reason.clone()).await?;
    }

    if let Some(status) = request.account_status.as_ref() {
        apply_account_status(&mut tx, account_id, actor.account_id, status, request.reason.clone()).await?;
    }

    sqlx::query(
        r#"
        update iam.account
        set row_version = row_version + 1,
            updated_at = now()
        where id = $1
        "#,
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.user.updated",
        "account",
        Some(account_id),
        Some("Administrator updated account details.".to_string()),
        json!({"reason": request.reason}),
        Some(&context.request_id),
    )
    .await?;

    shared::load_admin_user_summary(&state.pool, account_id).await
}

pub async fn list_admin_user_sessions(
    state: &AppState,
    account_id: Uuid,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<crate::api::contracts::Session>, Option<String>)> {
    shared::list_sessions(&state.pool, account_id, None, offset, limit).await
}

pub async fn revoke_admin_user_sessions(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    account_id: Uuid,
    request: SessionBulkRevokeRequest,
) -> AppResult<Acknowledgement> {
    let scope = request.scope.unwrap_or_else(|| "all".to_string());
    if scope == "others" {
        sqlx::query(
            r#"
            update auth.session
            set revoked_at = now(),
                revoke_reason_code = 'admin_revoke_others'
            where account_id = $1
              and revoked_at is null
            "#,
        )
        .bind(account_id)
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query(
            r#"
            update auth.session
            set revoked_at = now(),
                revoke_reason_code = 'admin_revoke_all'
            where account_id = $1
              and revoked_at is null
            "#,
        )
        .bind(account_id)
        .execute(&state.pool)
        .await?;
    }

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.user.sessions.revoked",
        "account",
        Some(account_id),
        Some("Administrator revoked sessions.".to_string()),
        json!({"scope": scope, "reason": request.reason}),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("User sessions revoked.".to_string()),
    })
}

pub async fn list_admin_user_security_events(
    state: &AppState,
    account_id: Uuid,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<crate::api::contracts::AdminSecurityEvent>, Option<String>)> {
    shared::list_security_events_admin(&state.pool, None, Some(account_id), offset, limit).await
}

pub async fn list_admin_user_audit_logs(
    state: &AppState,
    account_id: Uuid,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<crate::api::contracts::AuditLogEntry>, Option<String>)> {
    shared::list_audit_logs(&state.pool, None, Some(account_id), offset, limit).await
}

pub async fn admin_verify_user_email(state: &AppState, account_id: Uuid, email_id: Uuid) -> AppResult<EmailAddress> {
    let affected = sqlx::query(
        r#"
        update iam.account_email
        set verification_status = 'verified',
            verified_at = now(),
            updated_at = now()
        where id = $1 and account_id = $2 and deleted_at is null
        "#,
    )
    .bind(email_id)
    .bind(account_id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(AppError::not_found("email not found"));
    }
    shared::load_email_addresses(&state.pool, account_id)
        .await?
        .into_iter()
        .find(|email| email.id == email_id)
        .ok_or_else(|| AppError::not_found("email not found"))
}

pub async fn admin_unverify_user_email(state: &AppState, account_id: Uuid, email_id: Uuid) -> AppResult<EmailAddress> {
    let affected = sqlx::query(
        r#"
        update iam.account_email
        set verification_status = 'pending',
            verified_at = null,
            updated_at = now()
        where id = $1 and account_id = $2 and deleted_at is null
        "#,
    )
    .bind(email_id)
    .bind(account_id)
    .execute(&state.pool)
    .await?
    .rows_affected();
    if affected == 0 {
        return Err(AppError::not_found("email not found"));
    }
    shared::load_email_addresses(&state.pool, account_id)
        .await?
        .into_iter()
        .find(|email| email.id == email_id)
        .ok_or_else(|| AppError::not_found("email not found"))
}

pub async fn bulk_admin_user_action(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    request: AdminUserBulkActionRequest,
) -> AppResult<Acknowledgement> {
    for account_id in &request.account_ids {
        let mut tx = state.pool.begin().await?;
        match request.action.as_str() {
            "freeze" => apply_account_status(&mut tx, *account_id, actor.account_id, "frozen", request.reason.clone()).await?,
            "suspend" => apply_account_status(&mut tx, *account_id, actor.account_id, "suspended", request.reason.clone()).await?,
            "activate" | "restore" => apply_account_status(&mut tx, *account_id, actor.account_id, "active", request.reason.clone()).await?,
            "delete" => apply_account_status(&mut tx, *account_id, actor.account_id, "deleted", request.reason.clone()).await?,
            "set-status" => {
                let status = request
                    .status
                    .as_deref()
                    .ok_or_else(|| AppError::validation("status is required for set-status"))?;
                apply_account_status(&mut tx, *account_id, actor.account_id, status, request.reason.clone()).await?;
            }
            "revoke_sessions" => {
                sqlx::query(
                    r#"
                    update auth.session
                    set revoked_at = now(),
                        revoke_reason_code = 'bulk_revoke'
                    where account_id = $1 and revoked_at is null
                    "#,
                )
                .bind(account_id)
                .execute(&mut *tx)
                .await?;
            }
            "require_password_change" => {
                sqlx::query(
                    r#"
                    update auth.password_credential
                    set must_rotate = true
                    where authenticator_id in (
                        select id
                        from auth.authenticator
                        where account_id = $1
                          and authenticator_type = 'PASSWORD'
                          and revoked_at is null
                    )
                    "#,
                )
                .bind(account_id)
                .execute(&mut *tx)
                .await?;
            }
            _ => return Err(AppError::validation("unsupported bulk action")),
        }
        tx.commit().await?;
    }

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.user.bulk_action",
        "account",
        None,
        Some("Bulk account action applied.".to_string()),
        json!({"action": request.action, "accountIds": request.account_ids, "reason": request.reason}),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Bulk action accepted.".to_string()),
    })
}

pub async fn list_system_settings(state: &AppState) -> AppResult<Vec<AdminSystemSetting>> {
    shared::list_system_settings(&state.pool).await
}

pub async fn update_system_setting(
    state: &AppState,
    actor: &AuthContext,
    setting_key: &str,
    request: AdminSystemSettingUpdateRequest,
) -> AppResult<AdminSystemSetting> {
    let setting = shared::load_system_setting(&state.pool, setting_key).await?;

    sqlx::query(
        r#"
        update ops.system_setting
        set value_json = $2,
            updated_at = now(),
            updated_by_account_id = $3
        where id = $1
        "#,
    )
    .bind(setting.id)
    .bind(request.value)
    .bind(actor.account_id)
    .execute(&state.pool)
    .await?;

    shared::load_system_setting(&state.pool, setting_key).await
}

async fn upsert_admin_primary_email(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
    email: &str,
) -> AppResult<()> {
    let normalized = crate::utils::normalize_email(email);
    let existing = sqlx::query_scalar::<_, Uuid>(
        r#"
        select id
        from iam.account_email
        where account_id = $1 and normalized_email = $2 and deleted_at is null
        limit 1
        "#,
    )
    .bind(account_id)
    .bind(&normalized)
    .fetch_optional(&mut **tx)
    .await?;

    sqlx::query("update iam.account_email set is_primary_for_account = false where account_id = $1 and deleted_at is null")
        .bind(account_id)
        .execute(&mut **tx)
        .await?;

    if let Some(email_id) = existing {
        sqlx::query(
            r#"
            update iam.account_email
            set is_primary_for_account = true,
                is_login_enabled = true,
                verification_status = 'verified',
                verified_at = now(),
                updated_at = now()
            where id = $1
            "#,
        )
        .bind(email_id)
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query(
            r#"
            insert into iam.account_email (
                id, account_id, email, normalized_email, label, is_login_enabled, is_primary_for_account,
                verification_status, verified_at, created_at, updated_at
            )
            values ($1, $2, $3, $4, 'primary', true, true, 'verified', now(), now(), now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(email.trim())
        .bind(normalized)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

async fn upsert_admin_primary_phone(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
    phone: &str,
) -> AppResult<()> {
    sqlx::query("update iam.account_phone set is_primary_for_account = false where account_id = $1 and deleted_at is null")
        .bind(account_id)
        .execute(&mut **tx)
        .await?;

    let existing = sqlx::query_scalar::<_, Uuid>(
        r#"
        select id
        from iam.account_phone
        where account_id = $1 and e164_phone_number = $2 and deleted_at is null
        limit 1
        "#,
    )
    .bind(account_id)
    .bind(phone.trim())
    .fetch_optional(&mut **tx)
    .await?;

    if let Some(phone_id) = existing {
        sqlx::query(
            r#"
            update iam.account_phone
            set is_primary_for_account = true,
                verification_status = 'verified',
                verified_at = now(),
                updated_at = now()
            where id = $1
            "#,
        )
        .bind(phone_id)
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query(
            r#"
            insert into iam.account_phone (
                id, account_id, e164_phone_number, label, is_sms_enabled, is_primary_for_account, verification_status, verified_at, created_at, updated_at
            )
            values ($1, $2, $3, 'primary', false, true, 'verified', now(), now(), now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(phone.trim())
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

async fn set_login_disabled(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
    actor_account_id: Uuid,
    disable: bool,
    reason: Option<String>,
) -> AppResult<()> {
    if disable {
        sqlx::query(
            r#"
            insert into iam.account_restriction (
                id, account_id, restriction_type, status_code, reason_code, reason_text, starts_at, created_by_account_id, created_at
            )
            values ($1, $2, 'login_disabled', 'active', 'ADMIN_UPDATE', $3, now(), $4, now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(reason)
        .bind(actor_account_id)
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query(
            r#"
            update iam.account_restriction
            set status_code = 'lifted',
                lifted_at = now(),
                lifted_by_account_id = $2
            where account_id = $1
              and restriction_type = 'login_disabled'
              and status_code = 'active'
              and lifted_at is null
            "#,
        )
        .bind(account_id)
        .bind(actor_account_id)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

pub(crate) async fn apply_account_status(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
    actor_account_id: Uuid,
    status: &str,
    reason: Option<String>,
) -> AppResult<()> {
    match status {
        "active" | "pending" => {
            sqlx::query(
                r#"
                update iam.account
                set status_code = $2,
                    deleted_at = null,
                    updated_at = now()
                where id = $1
                "#,
            )
            .bind(account_id)
            .bind(status)
            .execute(&mut **tx)
            .await?;

            sqlx::query(
                r#"
                update iam.account_restriction
                set status_code = 'lifted',
                    lifted_at = now(),
                    lifted_by_account_id = $2
                where account_id = $1
                  and status_code = 'active'
                  and lifted_at is null
                "#,
            )
            .bind(account_id)
            .bind(actor_account_id)
            .execute(&mut **tx)
            .await?;
        }
        "email_unverified" => {
            sqlx::query("update iam.account set status_code = 'active', deleted_at = null, updated_at = now() where id = $1")
                .bind(account_id)
                .execute(&mut **tx)
                .await?;
            sqlx::query(
                r#"
                update iam.account_email
                set verification_status = 'pending',
                    verified_at = null,
                    updated_at = now()
                where account_id = $1
                  and is_primary_for_account = true
                  and deleted_at is null
                "#,
            )
            .bind(account_id)
            .execute(&mut **tx)
            .await?;
        }
        "password_reset_required" => {
            sqlx::query("update iam.account set status_code = 'active', deleted_at = null, updated_at = now() where id = $1")
                .bind(account_id)
                .execute(&mut **tx)
                .await?;
            sqlx::query(
                r#"
                update auth.password_credential
                set must_rotate = true
                where authenticator_id in (
                    select id
                    from auth.authenticator
                    where account_id = $1
                      and authenticator_type = 'PASSWORD'
                      and revoked_at is null
                )
                "#,
            )
            .bind(account_id)
            .execute(&mut **tx)
            .await?;
        }
        "suspended" | "frozen" => {
            let restriction_type = if status == "suspended" { "suspend" } else { "freeze" };
            sqlx::query("update iam.account set status_code = 'active', deleted_at = null, updated_at = now() where id = $1")
                .bind(account_id)
                .execute(&mut **tx)
                .await?;
            sqlx::query(
                r#"
                insert into iam.account_restriction (
                    id, account_id, restriction_type, status_code, reason_code, reason_text, starts_at, created_by_account_id, created_at
                )
                values ($1, $2, $3, 'active', 'ADMIN_STATUS_CHANGE', $4, now(), $5, now())
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(account_id)
            .bind(restriction_type)
            .bind(reason.clone())
            .bind(actor_account_id)
            .execute(&mut **tx)
            .await?;
            sqlx::query(
                r#"
                update auth.session
                set revoked_at = now(),
                    revoke_reason_code = $2
                where account_id = $1 and revoked_at is null
                "#,
            )
            .bind(account_id)
            .bind(restriction_type)
            .execute(&mut **tx)
            .await?;
        }
        "deleted" => {
            sqlx::query(
                r#"
                update iam.account
                set status_code = 'deleted',
                    deleted_at = now(),
                    updated_at = now()
                where id = $1
                "#,
            )
            .bind(account_id)
            .execute(&mut **tx)
            .await?;
            sqlx::query(
                r#"
                update auth.session
                set revoked_at = now(),
                    revoke_reason_code = 'account_deleted'
                where account_id = $1 and revoked_at is null
                "#,
            )
            .bind(account_id)
            .execute(&mut **tx)
            .await?;
        }
        _ => return Err(AppError::validation("unsupported account status")),
    }

    sqlx::query(
        r#"
        insert into iam.account_status_history (
            id, account_id, to_status_code, reason_code, reason_text, changed_by_account_id, changed_at
        )
        values ($1, $2, $3, 'ADMIN_STATUS_CHANGE', $4, $5, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(status)
    .bind(reason)
    .bind(actor_account_id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}
