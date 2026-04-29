use std::collections::HashSet;

use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    api::contracts::{
        Acknowledgement, AdminInvitationCode, AdminInvitationCreateRequest,
        AdminInvitationCreateResponse, AdminInvitationListQuery, AdminInvitationRevokeRequest,
        AdminInvitationSummary, AdminOverview, AdminRoleAssignmentRequest, AdminSystemSetting,
        AdminSystemSettingUpdateRequest, AdminUserBulkActionRequest, AdminUserCreateRequest,
        AdminUserCreateResponse, AdminUserSummary, AdminUserUpdateRequest, EmailAddress,
        PasswordPolicy, PermissionDefinition, RegisterRequest, RoleCreateRequest, RoleDefinition,
        RoleUpdateRequest, SessionBulkRevokeRequest,
    },
    auth::{self, AuthContext},
    error::{AppError, AppResult},
    request_context::RequestContext,
    services::{auth as auth_service, shared},
    utils::{normalize_email, normalize_phone_number, validate_username},
    AppState,
};

pub async fn list_roles(state: &AppState) -> AppResult<Vec<RoleDefinition>> {
    shared::list_roles(&state.pool).await
}

pub async fn list_permissions(state: &AppState) -> AppResult<Vec<PermissionDefinition>> {
    shared::list_permissions(&state.pool).await
}

pub async fn create_role(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    request: RoleCreateRequest,
) -> AppResult<RoleDefinition> {
    let code = normalize_role_code(&request.code)?;
    let name = validate_role_name(&request.name)?;
    let permission_codes = normalize_permission_codes(request.permission_codes.unwrap_or_default());
    ensure_permission_codes_exist(&state.pool, &permission_codes).await?;

    let exists =
        sqlx::query_scalar::<_, bool>("select exists (select 1 from iam.role where code = $1)")
            .bind(&code)
            .fetch_one(&state.pool)
            .await?;
    if exists {
        return Err(AppError::conflict("role code already exists"));
    }

    let mut tx = state.pool.begin().await?;
    let role_id = Uuid::new_v4();
    sqlx::query(
        r#"
        insert into iam.role (
            id, code, name, description, is_system_role, requires_mfa, created_at, updated_at
        )
        values ($1, $2, $3, $4, false, $5, now(), now())
        "#,
    )
    .bind(role_id)
    .bind(&code)
    .bind(&name)
    .bind(sanitize_nullable_text(request.description))
    .bind(request.requires_mfa.unwrap_or(false))
    .execute(&mut *tx)
    .await?;

    replace_role_permissions(&mut tx, role_id, &permission_codes).await?;
    tx.commit().await?;

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.role.created",
        "role",
        Some(role_id),
        Some("Administrator created a role.".to_string()),
        json!({ "roleCode": code, "permissionCodes": permission_codes }),
        Some(&context.request_id),
    )
    .await?;

    shared::load_role(&state.pool, &code).await
}

pub async fn update_role(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    role_code: &str,
    request: RoleUpdateRequest,
) -> AppResult<RoleDefinition> {
    let code = normalize_role_code(role_code)?;
    let role = shared::load_role(&state.pool, &code).await?;
    let permissions_requested = request.permission_codes.is_some();
    if role.is_system_role && (permissions_requested || request.requires_mfa.is_some()) {
        return Err(AppError::forbidden(
            "system role security settings cannot be edited through this endpoint",
        ));
    }

    let permission_codes = request
        .permission_codes
        .map(normalize_permission_codes)
        .unwrap_or_else(|| role.permission_codes.clone());
    ensure_permission_codes_exist(&state.pool, &permission_codes).await?;
    let name = request
        .name
        .as_deref()
        .map(validate_role_name)
        .transpose()?;

    let mut tx = state.pool.begin().await?;
    let role_id = sqlx::query_scalar::<_, Uuid>("select id from iam.role where code = $1")
        .bind(&code)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::not_found("role not found"))?;

    sqlx::query(
        r#"
        update iam.role
        set name = coalesce($2, name),
            description = case when $3::text is null then description else $3 end,
            requires_mfa = coalesce($4, requires_mfa),
            updated_at = now()
        where id = $1
        "#,
    )
    .bind(role_id)
    .bind(name)
    .bind(request.description.map(|value| value.trim().to_string()))
    .bind(request.requires_mfa)
    .execute(&mut *tx)
    .await?;

    if permissions_requested {
        replace_role_permissions(&mut tx, role_id, &permission_codes).await?;
    }

    tx.commit().await?;

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.role.updated",
        "role",
        Some(role_id),
        Some("Administrator updated a role.".to_string()),
        json!({ "roleCode": code, "permissionCodes": permission_codes }),
        Some(&context.request_id),
    )
    .await?;

    shared::load_role(&state.pool, &code).await
}

pub async fn delete_role(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    role_code: &str,
) -> AppResult<Acknowledgement> {
    let code = normalize_role_code(role_code)?;
    if matches!(code.as_str(), "admin" | "user") {
        return Err(AppError::forbidden(
            "admin and user roles cannot be deleted",
        ));
    }

    let row = sqlx::query(
        r#"
        select id
        from iam.role
        where code = $1
          and deleted_at is null
        "#,
    )
    .bind(&code)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("role not found"))?;
    let role_id: Uuid = row.try_get("id")?;

    let mut tx = state.pool.begin().await?;
    let expired_assignments = sqlx::query(
        r#"
        update iam.account_role
        set expires_at = now()
        where role_id = $1
          and (expires_at is null or expires_at > now())
        "#,
    )
    .bind(role_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    sqlx::query(
        r#"
        update iam.role
        set deleted_at = now(),
            updated_at = now()
        where id = $1
          and deleted_at is null
        "#,
    )
    .bind(role_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.role.deleted",
        "role",
        Some(role_id),
        Some("Administrator deleted a role and expired active assignments.".to_string()),
        json!({ "roleCode": code, "expiredAssignmentCount": expired_assignments }),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some(format!(
            "Role deleted; {expired_assignments} active assignment(s) expired."
        )),
    })
}

pub async fn admin_overview(state: &AppState) -> AppResult<AdminOverview> {
    shared::count_admin_overview(&state.pool, state.config.public_admin_bootstrap_enabled).await
}

pub async fn create_admin_invitations(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    request: AdminInvitationCreateRequest,
) -> AppResult<AdminInvitationCreateResponse> {
    if request.expires_at.is_some() && request.expires_in_seconds.is_some() {
        return Err(AppError::validation(
            "provide either expiresAt or expiresInSeconds, not both",
        ));
    }

    let count = request.count.unwrap_or(1).clamp(1, 100);
    let provided_code = request
        .code
        .as_deref()
        .map(validate_invitation_code)
        .transpose()?;
    if provided_code.is_some() && count != 1 {
        return Err(AppError::validation(
            "a custom invitation code can only be used when count is 1",
        ));
    }
    let max_uses = request.max_uses.unwrap_or(1).clamp(1, 100_000);
    let email = request
        .email
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let normalized_email = email.as_deref().map(normalize_email);
    let role_codes = request
        .role_codes
        .unwrap_or_else(|| vec!["user".to_string()])
        .into_iter()
        .map(|role| role.trim().to_ascii_lowercase())
        .filter(|role| !role.is_empty())
        .collect::<Vec<_>>();
    let role_codes = if role_codes.is_empty() {
        vec!["user".to_string()]
    } else {
        role_codes
    };
    ensure_role_codes_exist(&state.pool, &role_codes).await?;

    let expires_at = match (request.expires_at, request.expires_in_seconds) {
        (Some(value), None) => Some(value),
        (None, Some(seconds)) if seconds > 0 => Some(Utc::now() + Duration::seconds(seconds)),
        (None, Some(_)) => return Err(AppError::validation("expiresInSeconds must be positive")),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("validated above"),
    };

    let mut invitations = Vec::new();
    for _ in 0..count {
        let id = Uuid::new_v4();
        let code = provided_code
            .clone()
            .unwrap_or_else(|| format!("inv_{}", auth::generate_token(24)));
        let code_hash = auth::sha256_hex(&code);
        if provided_code.is_some() {
            let exists = sqlx::query_scalar::<_, bool>(
                "select exists (select 1 from auth.registration_invite where invite_code_hash = $1)",
            )
            .bind(&code_hash)
            .fetch_one(&state.pool)
            .await?;
            if exists {
                return Err(AppError::conflict("invitation code already exists"));
            }
        }
        let created_at = Utc::now();

        sqlx::query(
            r#"
            insert into auth.registration_invite (
                id, email, normalized_email, invite_code_hash, status, role_codes_json,
                expires_at, max_uses, use_count, created_by_account_id, created_at
            )
            values ($1, $2, $3, $4, 'active', $5, $6, $7, 0, $8, now())
            "#,
        )
        .bind(id)
        .bind(email.as_deref())
        .bind(normalized_email.as_deref())
        .bind(code_hash)
        .bind(json!(&role_codes))
        .bind(expires_at)
        .bind(max_uses)
        .bind(actor.account_id)
        .execute(&state.pool)
        .await?;

        invitations.push(AdminInvitationCode {
            id,
            code,
            email: email.clone(),
            role_codes: role_codes.clone(),
            max_uses,
            expires_at,
            created_at,
        });
    }

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.invitation.created",
        "registration_invite",
        None,
        Some("Administrator generated invitation code(s).".to_string()),
        json!({
            "count": count,
            "maxUses": max_uses,
            "roleCodes": role_codes,
            "email": email,
            "expiresAt": expires_at
        }),
        Some(&context.request_id),
    )
    .await?;

    Ok(AdminInvitationCreateResponse { invitations })
}

pub async fn list_admin_invitations(
    state: &AppState,
    query: AdminInvitationListQuery,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<AdminInvitationSummary>, Option<String>)> {
    let status = query
        .status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());

    let rows = sqlx::query(
        r#"
        select *
        from (
            select
                id,
                email,
                role_codes_json,
                case
                    when revoked_at is not null then 'revoked'
                    when status = 'active' and expires_at is not null and expires_at <= now() then 'expired'
                    else status
                end as effective_status,
                max_uses,
                use_count,
                expires_at,
                consumed_at,
                last_used_at,
                revoked_at,
                created_by_account_id,
                created_at
            from auth.registration_invite
        ) invites
        where ($1::text is null or effective_status = $1)
        order by created_at desc
        offset $2
        limit $3
        "#,
    )
    .bind(status)
    .bind(offset)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let next_cursor = has_more.then(|| crate::utils::encode_offset_cursor(offset + limit));
    let invitations = rows
        .into_iter()
        .take(limit as usize)
        .map(invitation_summary_from_row)
        .collect::<AppResult<Vec<_>>>()?;

    Ok((invitations, next_cursor))
}

pub async fn revoke_admin_invitation(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    invitation_id: Uuid,
    request: AdminInvitationRevokeRequest,
) -> AppResult<Acknowledgement> {
    let current_status = sqlx::query_scalar::<_, String>(
        r#"
        select status
        from auth.registration_invite
        where id = $1
        "#,
    )
    .bind(invitation_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("invitation not found"))?;

    if current_status == "consumed" {
        return Err(AppError::conflict("consumed invitations cannot be revoked"));
    }

    sqlx::query(
        r#"
        update auth.registration_invite
        set status = 'revoked',
            revoked_at = coalesce(revoked_at, now())
        where id = $1
        "#,
    )
    .bind(invitation_id)
    .execute(&state.pool)
    .await?;

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.invitation.revoked",
        "registration_invite",
        Some(invitation_id),
        Some("Administrator revoked an invitation code.".to_string()),
        json!({ "reason": request.reason }),
        Some(&context.request_id),
    )
    .await?;

    Ok(Acknowledgement {
        status: "ok".to_string(),
        message: Some("Invitation revoked.".to_string()),
    })
}

pub async fn get_password_policy(state: &AppState) -> AppResult<PasswordPolicy> {
    auth_service::load_password_policy(&state.pool).await
}

pub async fn update_password_policy(
    state: &AppState,
    actor: &AuthContext,
    context: &RequestContext,
    mut policy: PasswordPolicy,
) -> AppResult<PasswordPolicy> {
    if policy.min_length < 1 {
        return Err(AppError::validation("minLength must be at least 1"));
    }
    if policy.require_uppercase || policy.require_lowercase {
        policy.require_letter = true;
    }

    let setting = shared::load_system_setting(&state.pool, "auth.password.policy").await?;
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
    .bind(json!(&policy))
    .bind(actor.account_id)
    .execute(&state.pool)
    .await?;

    shared::record_audit_log(
        &state.pool,
        Some(actor.account_id),
        "admin.password_policy.updated",
        "system_setting",
        Some(setting.id),
        Some("Administrator updated the password policy.".to_string()),
        json!({ "policy": &policy }),
        Some(&context.request_id),
    )
    .await?;

    auth_service::load_password_policy(&state.pool).await
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
) -> AppResult<(
    Vec<crate::api::contracts::AdminSecurityEvent>,
    Option<String>,
)> {
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
        select id
        from (
            select distinct a.id, a.created_at
            from iam.account a
            join iam.account_profile p on p.account_id = a.id
            left join iam.account_email ae on ae.account_id = a.id and ae.is_primary_for_account = true and ae.deleted_at is null
            left join iam.account_phone ap on ap.account_id = a.id and ap.is_primary_for_account = true and ap.deleted_at is null
            left join iam.account_role ar
                on ar.account_id = a.id
               and (ar.expires_at is null or ar.expires_at > now())
            left join iam.role r on r.id = ar.role_id and r.deleted_at is null
            where ($1::text is null
                   or lower(coalesce(p.display_name, '')) ilike $1
                   or lower(coalesce(a.public_handle, '')) ilike $1
                   or lower(coalesce(ae.email, '')) ilike $1
                   or lower(coalesce(ap.e164_phone_number, '')) ilike $1
                   or cast(a.id as text) ilike $1)
              and ($2::text is null or r.code = $2)
        ) account_matches
        order by created_at desc
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
        if status
            .map(|expected| expected == summary.status)
            .unwrap_or(true)
        {
            summaries.push(summary);
        }
    }

    let total = summaries.len() as i64;
    let next_cursor =
        (offset + limit < total).then(|| crate::utils::encode_offset_cursor(offset + limit));
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
) -> AppResult<AdminUserCreateResponse> {
    let username = validate_username(&request.username)?;
    let initial_password = match request.password {
        Some(password) if !password.trim().is_empty() => password,
        _ => {
            auth_service::generate_initial_password(&state.pool, Some(&username), &request.email)
                .await?
        }
    };
    let requested_status = request.account_status.clone();
    let register_request = RegisterRequest {
        username: username.clone(),
        email: request.email,
        password: initial_password.clone(),
        display_name: request.display_name,
        primary_phone: request.primary_phone,
        invitation_code: None,
        accepted_legal_documents: Vec::new(),
    };
    if request.role_codes.is_some() && request.role_assignments.is_some() {
        return Err(AppError::validation(
            "provide either roleCodes or roleAssignments, not both",
        ));
    }
    let role_assignments =
        normalize_role_assignments(request.role_assignments, request.role_codes, true)?;
    let role_codes = role_assignments
        .iter()
        .map(|assignment| assignment.role_code.clone())
        .collect::<Vec<_>>();
    ensure_role_codes_exist(&state.pool, &role_codes).await?;
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
        None,
        false,
    )
    .await?;

    apply_role_assignment_expiries(
        &state.pool,
        created.account_id,
        actor.account_id,
        &role_assignments,
    )
    .await?;

    if let Some(status) = requested_status.as_deref() {
        if status != "active" && status != "pending" {
            let mut tx = state.pool.begin().await?;
            apply_account_status(
                &mut tx,
                created.account_id,
                actor.account_id,
                status,
                Some("Initial admin-created status".to_string()),
            )
            .await?;
            tx.commit().await?;
        }
    }

    let user = shared::load_admin_user_summary(&state.pool, created.account_id).await?;
    Ok(AdminUserCreateResponse {
        account_text: build_account_text(&user, &initial_password),
        initial_password,
        user,
    })
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

    if let Some(username) = request.username.as_ref() {
        let normalized = validate_username(username)?;
        ensure_username_available(&state.pool, account_id, &normalized).await?;
        sqlx::query(
            r#"
            update iam.account
            set public_handle = $2,
                username_changed_at = now(),
                updated_at = now()
            where id = $1
            "#,
        )
        .bind(account_id)
        .bind(normalized)
        .execute(&mut *tx)
        .await?;
    }

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

    if request.role_codes.is_some() && request.role_assignments.is_some() {
        return Err(AppError::validation(
            "provide either roleCodes or roleAssignments, not both",
        ));
    }

    if request.role_codes.is_some() || request.role_assignments.is_some() {
        let role_assignments = normalize_role_assignments(
            request.role_assignments.clone(),
            request.role_codes.clone(),
            false,
        )?;
        let role_codes = role_assignments
            .iter()
            .map(|assignment| assignment.role_code.clone())
            .collect::<Vec<_>>();
        ensure_role_codes_exist(&state.pool, &role_codes).await?;
        sqlx::query("delete from iam.account_role where account_id = $1")
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        for assignment in &role_assignments {
            sqlx::query(
                r#"
                insert into iam.account_role (
                    account_id, role_id, granted_by_account_id, granted_at, expires_at
                )
                select $1, id, $2, now(), $4
                from iam.role
                where code = $3
                  and deleted_at is null
                "#,
            )
            .bind(account_id)
            .bind(actor.account_id)
            .bind(&assignment.role_code)
            .bind(assignment.expires_at.as_ref().cloned())
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
        set_login_disabled(
            &mut tx,
            account_id,
            actor.account_id,
            disable_login,
            request.reason.clone(),
        )
        .await?;
    }

    if let Some(status) = request.account_status.as_ref() {
        apply_account_status(
            &mut tx,
            account_id,
            actor.account_id,
            status,
            request.reason.clone(),
        )
        .await?;
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
) -> AppResult<(
    Vec<crate::api::contracts::AdminSecurityEvent>,
    Option<String>,
)> {
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

pub async fn admin_verify_user_email(
    state: &AppState,
    account_id: Uuid,
    email_id: Uuid,
) -> AppResult<EmailAddress> {
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

pub async fn admin_unverify_user_email(
    state: &AppState,
    account_id: Uuid,
    email_id: Uuid,
) -> AppResult<EmailAddress> {
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
            "freeze" => {
                apply_account_status(
                    &mut tx,
                    *account_id,
                    actor.account_id,
                    "frozen",
                    request.reason.clone(),
                )
                .await?
            }
            "suspend" => {
                apply_account_status(
                    &mut tx,
                    *account_id,
                    actor.account_id,
                    "suspended",
                    request.reason.clone(),
                )
                .await?
            }
            "activate" | "restore" => {
                apply_account_status(
                    &mut tx,
                    *account_id,
                    actor.account_id,
                    "active",
                    request.reason.clone(),
                )
                .await?
            }
            "delete" => {
                apply_account_status(
                    &mut tx,
                    *account_id,
                    actor.account_id,
                    "deleted",
                    request.reason.clone(),
                )
                .await?
            }
            "set-status" => {
                let status = request
                    .status
                    .as_deref()
                    .ok_or_else(|| AppError::validation("status is required for set-status"))?;
                apply_account_status(
                    &mut tx,
                    *account_id,
                    actor.account_id,
                    status,
                    request.reason.clone(),
                )
                .await?;
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

fn invitation_summary_from_row(row: sqlx::postgres::PgRow) -> AppResult<AdminInvitationSummary> {
    let role_codes_json: serde_json::Value = row.try_get("role_codes_json")?;
    let role_codes = role_codes_json
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let max_uses: i32 = row.try_get("max_uses")?;
    let use_count: i32 = row.try_get("use_count")?;

    Ok(AdminInvitationSummary {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        role_codes,
        status: row.try_get("effective_status")?,
        max_uses,
        use_count,
        remaining_uses: (max_uses - use_count).max(0),
        expires_at: row.try_get("expires_at")?,
        consumed_at: row.try_get("consumed_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
        created_by_account_id: row.try_get("created_by_account_id")?,
        created_at: row.try_get("created_at")?,
    })
}

fn validate_invitation_code(code: &str) -> AppResult<String> {
    let trimmed = code.trim();
    if trimmed.len() < 6 || trimmed.len() > 128 {
        return Err(AppError::validation(
            "invitation code must be between 6 and 128 characters",
        ));
    }
    if !trimmed.chars().all(|ch| ch.is_ascii_graphic()) {
        return Err(AppError::validation(
            "invitation code may only contain visible ASCII characters without spaces",
        ));
    }
    Ok(trimmed.to_string())
}

fn normalize_role_code(role_code: &str) -> AppResult<String> {
    let code = role_code.trim().to_ascii_lowercase();
    if code.len() < 2 || code.len() > 40 {
        return Err(AppError::validation(
            "roleCode must be between 2 and 40 characters",
        ));
    }
    if !code
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        return Err(AppError::validation(
            "roleCode may contain only letters, numbers, underscores, and hyphens",
        ));
    }
    Ok(code)
}

fn validate_role_name(name: &str) -> AppResult<String> {
    let trimmed = name.trim();
    if trimmed.len() < 2 || trimmed.len() > 80 {
        return Err(AppError::validation(
            "role name must be between 2 and 80 characters",
        ));
    }
    Ok(trimmed.to_string())
}

fn sanitize_nullable_text(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn normalize_permission_codes(permission_codes: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for permission_code in permission_codes {
        let permission_code = permission_code.trim().to_ascii_lowercase();
        if !permission_code.is_empty() && seen.insert(permission_code.clone()) {
            normalized.push(permission_code);
        }
    }
    normalized
}

fn normalize_role_assignments(
    role_assignments: Option<Vec<AdminRoleAssignmentRequest>>,
    role_codes: Option<Vec<String>>,
    default_to_user: bool,
) -> AppResult<Vec<AdminRoleAssignmentRequest>> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    if let Some(assignments) = role_assignments {
        for assignment in assignments {
            let role_code = normalize_role_code(&assignment.role_code)?;
            if !seen.insert(role_code.clone()) {
                return Err(AppError::validation(
                    "duplicate roleCode in roleAssignments",
                ));
            }
            if assignment
                .expires_at
                .as_ref()
                .map(|expires_at| expires_at <= &Utc::now())
                .unwrap_or(false)
            {
                return Err(AppError::validation("role expiresAt must be in the future"));
            }
            normalized.push(AdminRoleAssignmentRequest {
                role_code,
                expires_at: assignment.expires_at,
            });
        }
    } else {
        let role_codes = role_codes.unwrap_or_else(|| {
            if default_to_user {
                vec!["user".to_string()]
            } else {
                Vec::new()
            }
        });
        for role_code in role_codes {
            let role_code = normalize_role_code(&role_code)?;
            if seen.insert(role_code.clone()) {
                normalized.push(AdminRoleAssignmentRequest {
                    role_code,
                    expires_at: None,
                });
            }
        }
    }

    if normalized.is_empty() {
        return Err(AppError::validation("at least one role is required"));
    }

    Ok(normalized)
}

async fn apply_role_assignment_expiries(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    actor_account_id: Uuid,
    assignments: &[AdminRoleAssignmentRequest],
) -> AppResult<()> {
    for assignment in assignments
        .iter()
        .filter(|assignment| assignment.expires_at.is_some())
    {
        sqlx::query(
            r#"
            update iam.account_role ar
            set expires_at = $4,
                granted_by_account_id = $2
            from iam.role r
            where ar.role_id = r.id
              and ar.account_id = $1
              and r.code = $3
              and r.deleted_at is null
            "#,
        )
        .bind(account_id)
        .bind(actor_account_id)
        .bind(&assignment.role_code)
        .bind(assignment.expires_at.as_ref().cloned())
        .execute(pool)
        .await?;
    }

    Ok(())
}

async fn replace_role_permissions(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
    permission_codes: &[String],
) -> AppResult<()> {
    sqlx::query("delete from iam.role_permission where role_id = $1")
        .bind(role_id)
        .execute(&mut **tx)
        .await?;

    for permission_code in permission_codes {
        sqlx::query(
            r#"
            insert into iam.role_permission (role_id, permission_id, granted_at)
            select $1, id, now()
            from iam.permission
            where code = $2
            "#,
        )
        .bind(role_id)
        .bind(permission_code)
        .execute(&mut **tx)
        .await?;
    }

    Ok(())
}

async fn ensure_permission_codes_exist(
    pool: &sqlx::PgPool,
    permission_codes: &[String],
) -> AppResult<()> {
    if permission_codes.is_empty() {
        return Ok(());
    }

    let existing = sqlx::query_scalar::<_, String>(
        r#"
        select code
        from iam.permission
        where code = any($1::text[])
        "#,
    )
    .bind(permission_codes.to_vec())
    .fetch_all(pool)
    .await?;

    let missing = permission_codes
        .iter()
        .filter(|permission_code| {
            !existing
                .iter()
                .any(|candidate| candidate == *permission_code)
        })
        .cloned()
        .collect::<Vec<_>>();

    if missing.is_empty() {
        Ok(())
    } else {
        Err(
            AppError::validation("one or more permission codes are invalid")
                .with_details(json!({ "missingPermissionCodes": missing })),
        )
    }
}

async fn ensure_role_codes_exist(pool: &sqlx::PgPool, role_codes: &[String]) -> AppResult<()> {
    let requested = role_codes
        .iter()
        .map(|role| role.trim().to_ascii_lowercase())
        .filter(|role| !role.is_empty())
        .collect::<Vec<_>>();
    if requested.is_empty() {
        return Err(AppError::validation("at least one role code is required"));
    }

    let existing = sqlx::query_scalar::<_, String>(
        r#"
        select code
        from iam.role
        where code = any($1::text[])
          and deleted_at is null
        "#,
    )
    .bind(requested.clone())
    .fetch_all(pool)
    .await?;

    let missing = requested
        .into_iter()
        .filter(|role| !existing.iter().any(|candidate| candidate == role))
        .collect::<Vec<_>>();

    if missing.is_empty() {
        Ok(())
    } else {
        Err(AppError::validation("one or more role codes are invalid")
            .with_details(json!({ "missingRoleCodes": missing })))
    }
}

async fn ensure_username_available(
    pool: &sqlx::PgPool,
    account_id: Uuid,
    username: &str,
) -> AppResult<()> {
    let exists = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from iam.account
            where public_handle is not null
              and lower(public_handle) = $1
              and id <> $2
              and deleted_at is null
        )
        "#,
    )
    .bind(username)
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    if exists {
        Err(AppError::conflict("username is already in use"))
    } else {
        Ok(())
    }
}

fn build_account_text(user: &AdminUserSummary, initial_password: &str) -> String {
    let mut lines = vec![
        "Account details".to_string(),
        format!("Name: {}", user.display_name),
    ];
    if let Some(username) = user.username.as_ref() {
        lines.push(format!("Username: {username}"));
    }
    lines.push(format!("Email: {}", user.primary_email));
    if let Some(phone) = user.primary_phone.as_ref() {
        lines.push(format!("Phone: {phone}"));
    }
    lines.push(format!("Password: {initial_password}"));
    lines.push(format!("Roles: {}", user.roles.join(", ")));
    lines.join("\n")
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
    let normalized_phone = normalize_phone_number(phone);
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
    .bind(&normalized_phone)
    .fetch_optional(&mut **tx)
    .await?;

    if let Some(phone_id) = existing {
        sqlx::query(
            r#"
            update iam.account_phone
            set is_primary_for_account = true,
                is_login_enabled = true,
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
                id, account_id, e164_phone_number, label, is_sms_enabled, is_primary_for_account,
                is_login_enabled, verification_status, verified_at, created_at, updated_at
            )
            values ($1, $2, $3, 'primary', false, true, true, 'verified', now(), now(), now())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(account_id)
        .bind(normalized_phone)
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
            let restriction_type = if status == "suspended" {
                "suspend"
            } else {
                "freeze"
            };
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
