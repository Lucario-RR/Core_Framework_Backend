use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;

use crate::{
    api::contracts::{
        AdminSecurityEvent, AdminSystemSetting, AdminUserSummary, AuditLogEntry, EmailAddress, FileRecord,
        Passkey, PhoneNumber, RoleDefinition, SecurityEvent, Session, UserProfile, UserSecuritySummary,
    },
    auth,
    error::{AppError, AppResult},
    utils::{encode_offset_cursor, normalize_email},
};

const EFFECTIVE_STATUS_SQL: &str = r#"
case
    when a.deleted_at is not null or a.status_code = 'deleted' then 'deleted'
    when exists (
        select 1
        from iam.account_restriction ar
        where ar.account_id = a.id
          and ar.restriction_type = 'freeze'
          and ar.status_code = 'active'
          and ar.lifted_at is null
          and (ar.ends_at is null or ar.ends_at > now())
    ) then 'frozen'
    when exists (
        select 1
        from iam.account_restriction ar
        where ar.account_id = a.id
          and ar.restriction_type = 'suspend'
          and ar.status_code = 'active'
          and ar.lifted_at is null
          and (ar.ends_at is null or ar.ends_at > now())
    ) then 'suspended'
    when exists (
        select 1
        from auth.authenticator au
        join auth.password_credential pc on pc.authenticator_id = au.id
        where au.account_id = a.id
          and au.authenticator_type = 'PASSWORD'
          and au.revoked_at is null
          and pc.must_rotate = true
    ) then 'password_reset_required'
    when not exists (
        select 1
        from iam.account_email ae
        where ae.account_id = a.id
          and ae.is_primary_for_account = true
          and ae.deleted_at is null
          and ae.verification_status = 'verified'
    ) then 'email_unverified'
    else a.status_code
end
"#;

#[derive(Debug, FromRow)]
struct AccountProfileRow {
    id: Uuid,
    status: String,
    created_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
    deleted_at: Option<DateTime<Utc>>,
    display_name: Option<String>,
    locale: String,
    timezone_name: String,
    default_currency: String,
    profile_bio: Option<String>,
    avatar_file_id: Option<Uuid>,
    avatar_filename: Option<String>,
    suspended_until: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct EmailRow {
    id: Uuid,
    email: String,
    label: String,
    is_primary: bool,
    is_login_enabled: bool,
    is_verified: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct PhoneRow {
    id: Uuid,
    phone_number: String,
    label: String,
    is_primary: bool,
    is_sms_enabled: bool,
    is_verified: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct SessionRow {
    id: Uuid,
    authenticated_aal: i16,
    device_label: Option<String>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    idle_expires_at: DateTime<Utc>,
    absolute_expires_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct SecurityEventRow {
    id: Uuid,
    event_type: String,
    severity: String,
    summary: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    device_label: Option<String>,
    occurred_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct AdminSecurityEventRow {
    id: Uuid,
    account_id: Uuid,
    account_email: Option<String>,
    event_type: String,
    severity: String,
    summary: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    device_label: Option<String>,
    occurred_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct AuditLogRow {
    id: Uuid,
    action: String,
    entity_type: String,
    entity_id: Option<Uuid>,
    actor_account_id: Option<Uuid>,
    summary: Option<String>,
    request_id: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct PasskeyRow {
    id: Uuid,
    display_name: Option<String>,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, FromRow)]
struct FileRecordRow {
    id: Uuid,
    filename: String,
    content_type: String,
    size: i64,
    purpose: String,
    status: String,
    metadata_stripped: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct SystemSettingRow {
    id: Uuid,
    key: String,
    scope: String,
    value_type: String,
    description: Option<String>,
    is_sensitive: bool,
    default_value: Value,
    value: Value,
    updated_at: Option<DateTime<Utc>>,
    updated_by_account_id: Option<Uuid>,
}

pub async fn get_global_setting_value(pool: &PgPool, key: &str) -> AppResult<Value> {
    let row = sqlx::query(
        r#"
        select coalesce(ss.value_json, sd.default_value_json) as value
        from ops.setting_definition sd
        left join ops.system_setting ss
            on ss.definition_id = sd.id
           and ss.scope = 'global'
           and ss.account_id is null
        where sd.key = $1
        "#,
    )
    .bind(key)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Err(AppError::not_found(format!("system setting {key} does not exist")));
    };

    row.try_get("value")
        .map_err(|error| AppError::internal(format!("failed to decode setting {key}: {error}")))
}

pub async fn get_global_setting_bool(pool: &PgPool, key: &str) -> AppResult<bool> {
    Ok(get_global_setting_value(pool, key)
        .await?
        .as_bool()
        .unwrap_or(false))
}

pub async fn get_global_setting_i64(pool: &PgPool, key: &str) -> AppResult<i64> {
    Ok(get_global_setting_value(pool, key)
        .await?
        .as_i64()
        .unwrap_or_default())
}

pub async fn get_account_setting_bool(pool: &PgPool, account_id: Uuid, key: &str) -> AppResult<bool> {
    let row = sqlx::query(
        r#"
        select value_json
        from ops.account_setting
        where account_id = $1 and setting_key = $2
        "#,
    )
    .bind(account_id)
    .bind(key)
    .fetch_optional(pool)
    .await?;

    Ok(row
        .and_then(|row| row.try_get::<Value, _>("value_json").ok())
        .and_then(|value| value.as_bool())
        .unwrap_or(false))
}

pub async fn load_email_addresses(pool: &PgPool, account_id: Uuid) -> AppResult<Vec<EmailAddress>> {
    let rows = sqlx::query_as::<_, EmailRow>(
        r#"
        select
            id,
            email,
            label,
            is_primary_for_account as is_primary,
            is_login_enabled,
            (verification_status = 'verified') as is_verified,
            created_at
        from iam.account_email
        where account_id = $1
          and deleted_at is null
        order by is_primary_for_account desc, created_at asc
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| EmailAddress {
            id: row.id,
            email: row.email,
            label: row.label,
            is_primary: row.is_primary,
            is_login_enabled: row.is_login_enabled,
            is_verified: row.is_verified,
            created_at: row.created_at,
        })
        .collect())
}

pub async fn load_phone_numbers(pool: &PgPool, account_id: Uuid) -> AppResult<Vec<PhoneNumber>> {
    let rows = sqlx::query_as::<_, PhoneRow>(
        r#"
        select
            id,
            e164_phone_number as phone_number,
            label,
            is_primary_for_account as is_primary,
            is_sms_enabled,
            (verification_status = 'verified') as is_verified,
            created_at
        from iam.account_phone
        where account_id = $1
          and deleted_at is null
        order by is_primary_for_account desc, created_at asc
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| PhoneNumber {
            id: row.id,
            phone_number: row.phone_number,
            label: row.label,
            is_primary: row.is_primary,
            is_sms_enabled: row.is_sms_enabled,
            is_verified: row.is_verified,
            created_at: row.created_at,
        })
        .collect())
}

pub async fn load_security_summary(pool: &PgPool, account_id: Uuid) -> AppResult<UserSecuritySummary> {
    let password_row = sqlx::query(
        r#"
        select pc.must_rotate
        from auth.authenticator a
        join auth.password_credential pc on pc.authenticator_id = a.id
        where a.account_id = $1
          and a.authenticator_type = 'PASSWORD'
          and a.revoked_at is null
        order by a.created_at desc
        limit 1
        "#,
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    let password_set = password_row.is_some();
    let must_rotate_password = password_row
        .as_ref()
        .and_then(|row| row.try_get::<bool, _>("must_rotate").ok())
        .unwrap_or(false);

    let email_rows = load_email_addresses(pool, account_id).await?;
    let phone_rows = load_phone_numbers(pool, account_id).await?;

    let email_verified = email_rows.iter().any(|email| email.is_verified);
    let primary_email_verified = email_rows
        .iter()
        .find(|email| email.is_primary)
        .map(|email| email.is_verified)
        .unwrap_or(false);
    let primary_phone_verified = phone_rows
        .iter()
        .find(|phone| phone.is_primary)
        .map(|phone| phone.is_verified)
        .unwrap_or(false);

    let totp_enabled = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from auth.authenticator a
            join auth.totp_factor tf on tf.authenticator_id = a.id
            where a.account_id = $1
              and a.authenticator_type = 'TOTP'
              and a.status = 'active'
              and a.revoked_at is null
              and tf.confirmed_at is not null
        )
        "#,
    )
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    let passkey_count = sqlx::query_scalar::<_, i64>(
        r#"
        select count(*)
        from auth.authenticator a
        join auth.passkey_credential pk on pk.authenticator_id = a.id
        where a.account_id = $1
          and a.authenticator_type = 'PASSKEY'
          and a.status = 'active'
          and a.revoked_at is null
        "#,
    )
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    let recovery_codes_available = sqlx::query_scalar::<_, bool>(
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
    .await?;

    let roles = sqlx::query_scalar::<_, String>(
        r#"
        select r.code
        from iam.account_role ar
        join iam.role r on r.id = ar.role_id
        where ar.account_id = $1
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    let any_role_requires_mfa = sqlx::query_scalar::<_, bool>(
        r#"
        select exists (
            select 1
            from iam.account_role ar
            join iam.role r on r.id = ar.role_id
            where ar.account_id = $1 and r.requires_mfa = true
        )
        "#,
    )
    .bind(account_id)
    .fetch_one(pool)
    .await?;

    let global_all_users = get_global_setting_bool(pool, "auth.mfa.required_for_all_users").await?;
    let global_admins = get_global_setting_bool(pool, "auth.mfa.required_for_admins").await?;
    let account_mfa_required = get_account_setting_bool(pool, account_id, "security.require_mfa_enrollment").await?;
    let is_admin = roles.iter().any(|role| role == "admin");
    let mfa_required = global_all_users || any_role_requires_mfa || account_mfa_required || (global_admins && is_admin);
    let mfa_enabled = totp_enabled || passkey_count > 0;

    let mut enrolled_factors = Vec::new();
    if password_set {
        enrolled_factors.push("password".to_string());
    }
    if totp_enabled {
        enrolled_factors.push("totp".to_string());
    }
    if passkey_count > 0 {
        enrolled_factors.push("passkey".to_string());
    }
    if recovery_codes_available {
        enrolled_factors.push("recovery_code".to_string());
    }

    Ok(UserSecuritySummary {
        password_set,
        must_rotate_password,
        email_verified,
        primary_email_verified,
        primary_phone_verified,
        mfa_enabled,
        mfa_required,
        totp_enabled,
        recovery_codes_available,
        passkey_count: passkey_count as i32,
        enrolled_factors,
    })
}

pub async fn load_user_profile(pool: &PgPool, account_id: Uuid) -> AppResult<UserProfile> {
    let sql = format!(
        r#"
        select
            a.id,
            {effective_status} as status,
            a.created_at,
            a.last_login_at,
            a.deleted_at,
            p.display_name,
            p.locale,
            p.timezone_name,
            p.default_currency,
            p.profile_bio,
            p.avatar_file_id,
            fa.original_filename as avatar_filename,
            (
                select max(ar.ends_at)
                from iam.account_restriction ar
                where ar.account_id = a.id
                  and ar.restriction_type = 'suspend'
                  and ar.status_code = 'active'
                  and ar.lifted_at is null
            ) as suspended_until
        from iam.account a
        join iam.account_profile p on p.account_id = a.id
        left join file.file_asset fa on fa.id = p.avatar_file_id
        where a.id = $1
        "#,
        effective_status = EFFECTIVE_STATUS_SQL
    );

    let base = sqlx::query_as::<_, AccountProfileRow>(&sql)
        .bind(account_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("account not found"))?;

    let emails = load_email_addresses(pool, account_id).await?;
    let phones = load_phone_numbers(pool, account_id).await?;
    let security = load_security_summary(pool, account_id).await?;
    let (roles, scopes) = auth::load_session_roles_and_scopes(pool, account_id).await?;

    let primary_email = emails
        .iter()
        .find(|email| email.is_primary)
        .map(|email| email.email.clone())
        .ok_or_else(|| AppError::conflict("account has no primary email"))?;

    let primary_phone = phones
        .iter()
        .find(|phone| phone.is_primary)
        .map(|phone| phone.phone_number.clone());

    Ok(UserProfile {
        id: base.id,
        status: base.status,
        primary_email,
        primary_phone,
        display_name: base.display_name.unwrap_or_else(|| "Unnamed User".to_string()),
        roles,
        scopes,
        default_currency: base.default_currency,
        locale: base.locale,
        timezone_name: base.timezone_name,
        profile_bio: base.profile_bio,
        avatar_file_id: base.avatar_file_id,
        avatar_filename: base.avatar_filename,
        email_count: emails.len() as i32,
        phone_count: phones.len() as i32,
        security,
        created_at: base.created_at,
    })
}

pub async fn load_admin_user_summary(pool: &PgPool, account_id: Uuid) -> AppResult<AdminUserSummary> {
    let sql = format!(
        r#"
        select
            a.id,
            {effective_status} as status,
            a.created_at,
            a.last_login_at,
            a.deleted_at,
            p.display_name,
            p.locale,
            p.timezone_name,
            p.default_currency,
            p.profile_bio,
            p.avatar_file_id,
            fa.original_filename as avatar_filename,
            (
                select max(ar.ends_at)
                from iam.account_restriction ar
                where ar.account_id = a.id
                  and ar.restriction_type = 'suspend'
                  and ar.status_code = 'active'
                  and ar.lifted_at is null
            ) as suspended_until
        from iam.account a
        join iam.account_profile p on p.account_id = a.id
        left join file.file_asset fa on fa.id = p.avatar_file_id
        where a.id = $1
        "#,
        effective_status = EFFECTIVE_STATUS_SQL
    );

    let base = sqlx::query_as::<_, AccountProfileRow>(&sql)
        .bind(account_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::not_found("account not found"))?;

    let emails = load_email_addresses(pool, account_id).await?;
    let phones = load_phone_numbers(pool, account_id).await?;
    let security = load_security_summary(pool, account_id).await?;
    let (roles, scopes) = auth::load_session_roles_and_scopes(pool, account_id).await?;

    let primary_email = emails
        .iter()
        .find(|email| email.is_primary)
        .map(|email| email.email.clone())
        .ok_or_else(|| AppError::conflict("account has no primary email"))?;

    let primary_phone = phones
        .iter()
        .find(|phone| phone.is_primary)
        .map(|phone| phone.phone_number.clone());

    Ok(AdminUserSummary {
        id: base.id,
        status: base.status,
        display_name: base.display_name.unwrap_or_else(|| "Unnamed User".to_string()),
        primary_email,
        primary_phone,
        roles,
        scopes,
        locale: base.locale,
        timezone_name: base.timezone_name,
        default_currency: base.default_currency,
        email_count: emails.len() as i32,
        phone_count: phones.len() as i32,
        avatar_file_id: base.avatar_file_id,
        avatar_filename: base.avatar_filename,
        profile_bio: base.profile_bio,
        created_at: base.created_at,
        last_active_at: base.last_login_at,
        deleted_at: base.deleted_at,
        suspended_until: base.suspended_until,
        security,
    })
}

pub async fn record_audit_log(
    pool: &PgPool,
    actor_account_id: Option<Uuid>,
    action: &str,
    entity_type: &str,
    entity_id: Option<Uuid>,
    summary: Option<String>,
    details_json: Value,
    request_id: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        insert into ops.audit_log (
            id, actor_account_id, action, entity_type, entity_id, summary, details_json, request_id, created_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(actor_account_id)
    .bind(action)
    .bind(entity_type)
    .bind(entity_id)
    .bind(summary)
    .bind(details_json)
    .bind(request_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn record_security_event(
    pool: &PgPool,
    account_id: Option<Uuid>,
    event_type: &str,
    severity: &str,
    summary: Option<String>,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    device_label: Option<&str>,
    details_json: Value,
    request_id: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        insert into ops.security_event (
            id, account_id, event_type, severity, summary, ip_address, user_agent, device_label, details_json, request_id, created_at
        )
        values ($1, $2, $3, $4, $5, nullif($6, '')::inet, $7, $8, $9, $10, now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(event_type)
    .bind(severity)
    .bind(summary)
    .bind(ip_address.unwrap_or_default())
    .bind(user_agent)
    .bind(device_label)
    .bind(details_json)
    .bind(request_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn queue_notification(
    pool: &PgPool,
    account_id: Option<Uuid>,
    template_code: &str,
    channel_type: &str,
    subject: Option<String>,
    body_json: Value,
) -> AppResult<()> {
    let notification_id = Uuid::new_v4();

    sqlx::query(
        r#"
        insert into ops.notification (
            id, account_id, template_code, channel_type, status, subject, body_json, created_at
        )
        values ($1, $2, $3, $4, 'queued', $5, $6, now())
        "#,
    )
    .bind(notification_id)
    .bind(account_id)
    .bind(template_code)
    .bind(channel_type)
    .bind(subject)
    .bind(body_json)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        insert into ops.notification_delivery (
            id, notification_id, channel_type, status, created_at
        )
        values ($1, $2, $3, 'queued', now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(notification_id)
    .bind(channel_type)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn list_sessions(
    pool: &PgPool,
    account_id: Uuid,
    current_session_id: Option<Uuid>,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<Session>, Option<String>)> {
    let rows = sqlx::query_as::<_, SessionRow>(
        r#"
        select
            id,
            authenticated_aal,
            device_label,
            user_agent,
            host(ip_address) as ip_address,
            created_at,
            last_seen_at,
            idle_expires_at,
            absolute_expires_at
        from auth.session
        where account_id = $1
          and revoked_at is null
        order by created_at desc
        offset $2
        limit $3
        "#,
    )
    .bind(account_id)
    .bind(offset)
    .bind(limit + 1)
    .fetch_all(pool)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let next_cursor = has_more.then(|| encode_offset_cursor(offset + limit));
    let rows = rows.into_iter().take(limit as usize);

    Ok((
        rows.map(|row| Session {
            id: row.id,
            is_current: current_session_id.map(|current| current == row.id).unwrap_or(false),
            authenticated_aal: row.authenticated_aal as i32,
            device_label: row.device_label,
            user_agent: row.user_agent,
            ip_address: row.ip_address,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
            idle_expires_at: row.idle_expires_at,
            absolute_expires_at: row.absolute_expires_at,
        })
        .collect(),
        next_cursor,
    ))
}

pub async fn list_security_events_for_account(
    pool: &PgPool,
    account_id: Uuid,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<SecurityEvent>, Option<String>)> {
    let rows = sqlx::query_as::<_, SecurityEventRow>(
        r#"
        select
            id,
            event_type,
            severity,
            summary,
            host(ip_address) as ip_address,
            user_agent,
            device_label,
            created_at as occurred_at
        from ops.security_event
        where account_id = $1
        order by created_at desc
        offset $2
        limit $3
        "#,
    )
    .bind(account_id)
    .bind(offset)
    .bind(limit + 1)
    .fetch_all(pool)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let next_cursor = has_more.then(|| encode_offset_cursor(offset + limit));

    Ok((
        rows.into_iter()
            .take(limit as usize)
            .map(|row| SecurityEvent {
                id: row.id,
                event_type: row.event_type,
                severity: row.severity,
                summary: row.summary,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                device_label: row.device_label,
                occurred_at: row.occurred_at,
            })
            .collect(),
        next_cursor,
    ))
}

pub async fn list_security_events_admin(
    pool: &PgPool,
    search: Option<&str>,
    account_id: Option<Uuid>,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<AdminSecurityEvent>, Option<String>)> {
    let search = search
        .map(normalize_email)
        .map(|value| format!("%{value}%"));

    let rows = sqlx::query_as::<_, AdminSecurityEventRow>(
        r#"
        select
            se.id,
            se.account_id,
            ae.email as account_email,
            se.event_type,
            se.severity,
            se.summary,
            host(se.ip_address) as ip_address,
            se.user_agent,
            se.device_label,
            se.created_at as occurred_at
        from ops.security_event se
        left join iam.account_email ae
            on ae.account_id = se.account_id
           and ae.is_primary_for_account = true
           and ae.deleted_at is null
        where ($1::text is null or ae.normalized_email ilike $1 or coalesce(se.summary, '') ilike $1)
          and ($2::uuid is null or se.account_id = $2)
        order by se.created_at desc
        offset $3
        limit $4
        "#,
    )
    .bind(search)
    .bind(account_id)
    .bind(offset)
    .bind(limit + 1)
    .fetch_all(pool)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let next_cursor = has_more.then(|| encode_offset_cursor(offset + limit));

    Ok((
        rows.into_iter()
            .take(limit as usize)
            .map(|row| AdminSecurityEvent {
                id: row.id,
                account_id: row.account_id,
                account_email: row.account_email,
                event_type: row.event_type,
                severity: row.severity,
                summary: row.summary,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                device_label: row.device_label,
                occurred_at: row.occurred_at,
            })
            .collect(),
        next_cursor,
    ))
}

pub async fn list_audit_logs(
    pool: &PgPool,
    search: Option<&str>,
    account_id: Option<Uuid>,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<AuditLogEntry>, Option<String>)> {
    let search = search.map(|value| format!("%{}%", value.trim().to_ascii_lowercase()));
    let rows = sqlx::query_as::<_, AuditLogRow>(
        r#"
        select
            id,
            action,
            entity_type,
            entity_id,
            actor_account_id,
            summary,
            request_id,
            created_at
        from ops.audit_log
        where ($1::text is null or lower(action) ilike $1 or lower(coalesce(summary, '')) ilike $1)
          and ($2::uuid is null or actor_account_id = $2 or entity_id = $2)
        order by created_at desc
        offset $3
        limit $4
        "#,
    )
    .bind(search)
    .bind(account_id)
    .bind(offset)
    .bind(limit + 1)
    .fetch_all(pool)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let next_cursor = has_more.then(|| encode_offset_cursor(offset + limit));

    Ok((
        rows.into_iter()
            .take(limit as usize)
            .map(|row| AuditLogEntry {
                id: row.id,
                action: row.action,
                entity_type: row.entity_type,
                entity_id: row.entity_id,
                actor_account_id: row.actor_account_id,
                summary: row.summary,
                request_id: row.request_id,
                created_at: row.created_at,
            })
            .collect(),
        next_cursor,
    ))
}

pub async fn list_passkeys(pool: &PgPool, account_id: Uuid) -> AppResult<Vec<Passkey>> {
    let rows = sqlx::query_as::<_, PasskeyRow>(
        r#"
        select
            a.id,
            a.display_label as display_name,
            a.created_at,
            a.last_used_at
        from auth.authenticator a
        join auth.passkey_credential pk on pk.authenticator_id = a.id
        where a.account_id = $1
          and a.authenticator_type = 'PASSKEY'
          and a.revoked_at is null
        order by a.created_at desc
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| Passkey {
            id: row.id,
            display_name: row.display_name.unwrap_or_else(|| "Unnamed passkey".to_string()),
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        })
        .collect())
}

pub async fn load_file_record(pool: &PgPool, file_id: Uuid, owner_account_id: Option<Uuid>) -> AppResult<FileRecord> {
    let row = sqlx::query_as::<_, FileRecordRow>(
        r#"
        select
            fa.id,
            fa.original_filename as filename,
            fa.content_type,
            fa.size_bytes as size,
            fa.purpose_code as purpose,
            fa.status,
            fa.metadata_stripped,
            fa.created_at
        from file.file_asset fa
        where fa.id = $1
          and fa.deleted_at is null
          and ($2::uuid is null or fa.owner_account_id = $2)
        "#,
    )
    .bind(file_id)
    .bind(owner_account_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found("file not found"))?;

    Ok(FileRecord {
        id: row.id,
        filename: row.filename,
        content_type: row.content_type,
        size: row.size,
        purpose: row.purpose,
        status: row.status,
        metadata_stripped: row.metadata_stripped,
        created_at: row.created_at,
    })
}

pub async fn list_roles(pool: &PgPool) -> AppResult<Vec<RoleDefinition>> {
    let role_rows = sqlx::query(
        r#"
        select id, code, name, description, requires_mfa
        from iam.role
        order by code asc
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut roles = Vec::new();
    for row in role_rows {
        let role_id: Uuid = row.try_get("id")?;
        let permissions = sqlx::query_scalar::<_, String>(
            r#"
            select p.code
            from iam.role_permission rp
            join iam.permission p on p.id = rp.permission_id
            where rp.role_id = $1
            order by p.code asc
            "#,
        )
        .bind(role_id)
        .fetch_all(pool)
        .await?;

        roles.push(RoleDefinition {
            code: row.try_get("code")?,
            name: row.try_get("name")?,
            description: row.try_get("description").ok(),
            requires_mfa: row.try_get("requires_mfa")?,
            permission_codes: permissions,
        });
    }

    Ok(roles)
}

pub async fn list_system_settings(pool: &PgPool) -> AppResult<Vec<AdminSystemSetting>> {
    let rows = sqlx::query_as::<_, SystemSettingRow>(
        r#"
        select
            ss.id,
            sd.key,
            ss.scope,
            sd.value_type,
            sd.description,
            sd.is_sensitive,
            sd.default_value_json as default_value,
            ss.value_json as value,
            ss.updated_at,
            ss.updated_by_account_id
        from ops.setting_definition sd
        join ops.system_setting ss on ss.definition_id = sd.id and ss.scope = 'global' and ss.account_id is null
        order by sd.key asc
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| AdminSystemSetting {
            id: row.id,
            key: row.key,
            scope: row.scope,
            value_type: row.value_type,
            description: row.description,
            is_sensitive: row.is_sensitive,
            default_value: row.default_value,
            value: row.value,
            updated_at: row.updated_at,
            updated_by_account_id: row.updated_by_account_id,
        })
        .collect())
}

pub async fn load_system_setting(pool: &PgPool, key: &str) -> AppResult<AdminSystemSetting> {
    let row = sqlx::query_as::<_, SystemSettingRow>(
        r#"
        select
            ss.id,
            sd.key,
            ss.scope,
            sd.value_type,
            sd.description,
            sd.is_sensitive,
            sd.default_value_json as default_value,
            ss.value_json as value,
            ss.updated_at,
            ss.updated_by_account_id
        from ops.setting_definition sd
        join ops.system_setting ss on ss.definition_id = sd.id and ss.scope = 'global' and ss.account_id is null
        where sd.key = $1
        "#,
    )
    .bind(key)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found("system setting not found"))?;

    Ok(AdminSystemSetting {
        id: row.id,
        key: row.key,
        scope: row.scope,
        value_type: row.value_type,
        description: row.description,
        is_sensitive: row.is_sensitive,
        default_value: row.default_value,
        value: row.value,
        updated_at: row.updated_at,
        updated_by_account_id: row.updated_by_account_id,
    })
}

pub async fn count_admin_overview(pool: &PgPool, public_bootstrap_enabled: bool) -> AppResult<crate::api::contracts::AdminOverview> {
    let account_count = sqlx::query_scalar::<_, i64>("select count(*) from iam.account").fetch_one(pool).await?;
    let active_account_count =
        sqlx::query_scalar::<_, i64>("select count(*) from iam.account where deleted_at is null and status_code = 'active'")
            .fetch_one(pool)
            .await?;
    let suspended_account_count = sqlx::query_scalar::<_, i64>(
        r#"
        select count(distinct account_id)
        from iam.account_restriction
        where restriction_type = 'suspend'
          and status_code = 'active'
          and lifted_at is null
          and (ends_at is null or ends_at > now())
        "#,
    )
    .fetch_one(pool)
    .await?;
    let deleted_account_count =
        sqlx::query_scalar::<_, i64>("select count(*) from iam.account where deleted_at is not null or status_code = 'deleted'")
            .fetch_one(pool)
            .await?;
    let admin_account_count = sqlx::query_scalar::<_, i64>(
        r#"
        select count(distinct ar.account_id)
        from iam.account_role ar
        join iam.role r on r.id = ar.role_id
        where r.code = 'admin'
        "#,
    )
    .fetch_one(pool)
    .await?;
    let role_count = sqlx::query_scalar::<_, i64>("select count(*) from iam.role").fetch_one(pool).await?;
    let active_session_count =
        sqlx::query_scalar::<_, i64>("select count(*) from auth.session where revoked_at is null and absolute_expires_at > now()")
            .fetch_one(pool)
            .await?;
    let security_event_count = sqlx::query_scalar::<_, i64>("select count(*) from ops.security_event").fetch_one(pool).await?;
    let audit_log_count = sqlx::query_scalar::<_, i64>("select count(*) from ops.audit_log").fetch_one(pool).await?;
    let privacy_request_count =
        sqlx::query_scalar::<_, i64>("select count(*) from privacy.data_subject_request").fetch_one(pool).await?;
    let system_setting_count = sqlx::query_scalar::<_, i64>("select count(*) from ops.system_setting").fetch_one(pool).await?;

    Ok(crate::api::contracts::AdminOverview {
        account_count,
        active_account_count,
        suspended_account_count,
        deleted_account_count,
        admin_account_count,
        role_count,
        active_session_count,
        security_event_count,
        audit_log_count,
        privacy_request_count,
        system_setting_count,
        public_admin_bootstrap_enabled: public_bootstrap_enabled,
    })
}

pub fn security_event_detail(account_id: Uuid, extra: Value) -> Value {
    json!({
        "accountId": account_id,
        "extra": extra,
    })
}
