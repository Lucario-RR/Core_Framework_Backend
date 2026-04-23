use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use crate::{
    api::contracts::{
        CookiePreferences, CookiePreferencesUpdateRequest, LegalDocument, PrivacyConsent, PrivacyConsentCreateRequest,
        PrivacyRequest, PrivacyRequestCreateRequest,
    },
    auth::AuthContext,
    error::{AppError, AppResult},
    services::shared,
    AppState,
};

#[derive(Debug, FromRow)]
struct LegalDocumentRow {
    document_key: String,
    title: String,
    version: String,
    effective_at: chrono::DateTime<Utc>,
    url: String,
}

#[derive(Debug, FromRow)]
struct ConsentRow {
    document_key: String,
    version: String,
    accepted_at: chrono::DateTime<Utc>,
    source: Option<String>,
}

#[derive(Debug, FromRow)]
struct PrivacyRequestRow {
    id: Uuid,
    request_type: String,
    status: String,
    requested_at: chrono::DateTime<Utc>,
    due_at: Option<chrono::DateTime<Utc>>,
    completed_at: Option<chrono::DateTime<Utc>>,
    notes: Option<String>,
    export_file_id: Option<Uuid>,
}

pub async fn list_legal_documents(state: &AppState) -> AppResult<Vec<LegalDocument>> {
    let rows = sqlx::query_as::<_, LegalDocumentRow>(
        r#"
        select document_key, title, version, effective_at, url
        from privacy.legal_document
        where is_current = true
        order by document_key asc
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| LegalDocument {
            document_key: row.document_key,
            title: row.title,
            version: row.version,
            effective_at: row.effective_at,
            url: row.url,
        })
        .collect())
}

pub async fn list_privacy_consents(state: &AppState, auth_context: &AuthContext) -> AppResult<Vec<PrivacyConsent>> {
    let rows = sqlx::query_as::<_, ConsentRow>(
        r#"
        select
            cr.purpose_code as document_key,
            pnv.version_label as version,
            cr.captured_at as accepted_at,
            cr.evidence_json ->> 'source' as source
        from privacy.consent_record cr
        left join privacy.privacy_notice_version pnv on pnv.id = cr.notice_version_id
        where cr.account_id = $1
          and cr.consent_status = 'granted'
        order by cr.captured_at desc
        "#,
    )
    .bind(auth_context.account_id)
    .fetch_all(&state.pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| PrivacyConsent {
            document_key: row.document_key,
            version: row.version,
            accepted_at: row.accepted_at,
            source: row.source,
        })
        .collect())
}

pub async fn create_privacy_consents(
    state: &AppState,
    auth_context: &AuthContext,
    request: PrivacyConsentCreateRequest,
) -> AppResult<Vec<PrivacyConsent>> {
    if request.documents.is_empty() {
        return Err(AppError::validation("documents must contain at least one item"));
    }

    for document in request.documents {
        let notice_type = match document.document_key.as_str() {
            "terms_of_service" => "TERMS",
            "privacy_policy" => "PRIVACY",
            "cookie_policy" => "COOKIE",
            _ => return Err(AppError::validation("unsupported document key")),
        };

        sqlx::query(
            r#"
            insert into privacy.consent_record (
                id, account_id, purpose_code, notice_version_id, consent_status, captured_via, evidence_json, captured_at
            )
            values (
                $1, $2, $3,
                (
                    select id
                    from privacy.privacy_notice_version
                    where notice_type = $4 and version_label = $5
                    order by published_at desc
                    limit 1
                ),
                'granted', 'api', $6, now()
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(auth_context.account_id)
        .bind(document.document_key)
        .bind(notice_type)
        .bind(document.version)
        .bind(json!({"source": "settings_update"}))
        .execute(&state.pool)
        .await?;
    }

    list_privacy_consents(state, auth_context).await
}

pub async fn list_privacy_requests(
    state: &AppState,
    auth_context: &AuthContext,
    offset: i64,
    limit: i64,
) -> AppResult<(Vec<PrivacyRequest>, Option<String>)> {
    let rows = sqlx::query_as::<_, PrivacyRequestRow>(
        r#"
        select
            id,
            request_type,
            status,
            requested_at,
            due_at,
            completed_at,
            notes,
            export_file_asset_id as export_file_id
        from privacy.data_subject_request
        where account_id = $1
        order by requested_at desc
        offset $2
        limit $3
        "#,
    )
    .bind(auth_context.account_id)
    .bind(offset)
    .bind(limit + 1)
    .fetch_all(&state.pool)
    .await?;

    let has_more = rows.len() as i64 > limit;
    let next_cursor = has_more.then(|| crate::utils::encode_offset_cursor(offset + limit));

    Ok((
        rows.into_iter()
            .take(limit as usize)
            .map(map_privacy_request)
            .collect(),
        next_cursor,
    ))
}

pub async fn create_privacy_request(
    state: &AppState,
    auth_context: &AuthContext,
    request: PrivacyRequestCreateRequest,
) -> AppResult<PrivacyRequest> {
    let request_id = Uuid::new_v4();
    let due_at = Utc::now() + Duration::days(30);
    sqlx::query(
        r#"
        insert into privacy.data_subject_request (
            id, account_id, request_type, status, requested_at, due_at, notes
        )
        values ($1, $2, $3, 'open', now(), $4, $5)
        "#,
    )
    .bind(request_id)
    .bind(auth_context.account_id)
    .bind(request.request_type)
    .bind(due_at)
    .bind(request.notes)
    .execute(&state.pool)
    .await?;

    get_privacy_request(state, auth_context, request_id).await
}

pub async fn get_privacy_request(
    state: &AppState,
    auth_context: &AuthContext,
    privacy_request_id: Uuid,
) -> AppResult<PrivacyRequest> {
    let row = sqlx::query_as::<_, PrivacyRequestRow>(
        r#"
        select
            id,
            request_type,
            status,
            requested_at,
            due_at,
            completed_at,
            notes,
            export_file_asset_id as export_file_id
        from privacy.data_subject_request
        where id = $1 and account_id = $2
        "#,
    )
    .bind(privacy_request_id)
    .bind(auth_context.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("privacy request not found"))?;

    Ok(map_privacy_request(row))
}

pub async fn get_cookie_preferences(
    state: &AppState,
    account_id: Option<Uuid>,
    anonymous_subject_hash: Option<String>,
) -> AppResult<CookiePreferences> {
    let row = sqlx::query(
        r#"
        select preferences_allowed, analytics_allowed, marketing_allowed, updated_at
        from privacy.cookie_consent
        where ($1::uuid is not null and account_id = $1)
           or ($1::uuid is null and $2::text is not null and anonymous_subject_token_hash = $2)
        order by updated_at desc
        limit 1
        "#,
    )
    .bind(account_id)
    .bind(anonymous_subject_hash)
    .fetch_optional(&state.pool)
    .await?;

    if let Some(row) = row {
        Ok(CookiePreferences {
            necessary: true,
            preferences: row.try_get("preferences_allowed")?,
            analytics: row.try_get("analytics_allowed")?,
            marketing: row.try_get("marketing_allowed")?,
            updated_at: row.try_get("updated_at")?,
        })
    } else {
        Ok(CookiePreferences {
            necessary: true,
            preferences: false,
            analytics: false,
            marketing: false,
            updated_at: Utc::now(),
        })
    }
}

pub async fn set_cookie_preferences(
    state: &AppState,
    account_id: Option<Uuid>,
    anonymous_subject_hash: Option<String>,
    request: CookiePreferencesUpdateRequest,
) -> AppResult<CookiePreferences> {
    sqlx::query(
        r#"
        insert into privacy.cookie_consent (
            id, account_id, anonymous_subject_token_hash, preferences_allowed, analytics_allowed, marketing_allowed, captured_at, updated_at
        )
        values ($1, $2, $3, $4, $5, $6, now(), now())
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(account_id)
    .bind(anonymous_subject_hash.clone())
    .bind(request.preferences)
    .bind(request.analytics)
    .bind(request.marketing)
    .execute(&state.pool)
    .await?;

    get_cookie_preferences(state, account_id, anonymous_subject_hash).await
}

fn map_privacy_request(row: PrivacyRequestRow) -> PrivacyRequest {
    PrivacyRequest {
        id: row.id,
        request_type: row.request_type,
        status: row.status,
        requested_at: row.requested_at,
        due_at: row.due_at,
        completed_at: row.completed_at,
        notes: row.notes,
        export_file_id: row.export_file_id,
    }
}
