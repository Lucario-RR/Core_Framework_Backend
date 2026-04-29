use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseMeta {
    pub request_id: String,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub data: T,
    pub meta: ResponseMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acknowledgement {
    pub status: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalDocumentAcceptance {
    pub document_key: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub primary_phone: Option<String>,
    pub invitation_code: Option<String>,
    pub accepted_legal_documents: Vec<LegalDocumentAcceptance>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoginRequest {
    pub login: Option<String>,
    pub email: Option<String>,
    pub username: Option<String>,
    #[serde(alias = "phone")]
    pub phone_number: Option<String>,
    pub password: String,
    pub remember_me: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordPolicy {
    pub min_length: i64,
    pub require_letter: bool,
    pub require_number: bool,
    pub require_special: bool,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub disallow_username: bool,
    pub disallow_email: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSecuritySummary {
    pub password_set: bool,
    pub must_rotate_password: bool,
    pub email_verified: bool,
    pub primary_email_verified: bool,
    pub primary_phone_verified: bool,
    pub mfa_enabled: bool,
    pub mfa_required: bool,
    pub totp_enabled: bool,
    pub recovery_codes_available: bool,
    pub passkey_count: i32,
    pub enrolled_factors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    pub id: Uuid,
    pub username: Option<String>,
    pub status: String,
    pub primary_email: String,
    pub primary_phone: Option<String>,
    pub display_name: String,
    pub roles: Vec<String>,
    pub scopes: Vec<String>,
    pub default_currency: String,
    pub locale: String,
    pub timezone_name: String,
    pub profile_bio: Option<String>,
    pub avatar_file_id: Option<Uuid>,
    pub avatar_filename: Option<String>,
    pub email_count: i32,
    pub phone_count: i32,
    pub security: UserSecuritySummary,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthSession {
    pub access_token: String,
    pub token_type: String,
    pub expires_in_seconds: i64,
    pub user: UserProfile,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileUpdateRequest {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub default_currency: Option<String>,
    pub locale: Option<String>,
    pub timezone_name: Option<String>,
    pub profile_bio: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AvatarUpdateRequest {
    pub file_id: Uuid,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordForgotRequest {
    pub email: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordResetRequest {
    pub reset_token: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaChallenge {
    pub challenge_id: Uuid,
    pub available_factors: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MfaVerifyRequest {
    pub challenge_id: Uuid,
    pub factor_type: String,
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    pub id: Uuid,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyRegistrationOptionsRequest {
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyRegistrationOptions {
    pub registration_id: Uuid,
    pub public_key: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyRegistrationVerifyRequest {
    pub registration_id: Uuid,
    pub credential: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyAuthenticationOptionsRequest {
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticationOptions {
    pub authentication_id: Uuid,
    pub public_key: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyAuthenticationVerifyRequest {
    pub authentication_id: Uuid,
    pub credential: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetup {
    pub secret: String,
    pub otpauth_uri: String,
    pub qr_code_svg_data_url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TotpEnableRequest {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeList {
    pub codes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationCodeRequest {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAddress {
    pub id: Uuid,
    pub email: String,
    pub label: String,
    pub is_primary: bool,
    pub is_login_enabled: bool,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailAddressCreateRequest {
    pub email: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneNumber {
    pub id: Uuid,
    pub phone_number: String,
    pub label: String,
    pub is_login_enabled: bool,
    pub is_primary: bool,
    pub is_sms_enabled: bool,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhoneNumberCreateRequest {
    pub phone_number: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalDocument {
    pub document_key: String,
    pub title: String,
    pub version: String,
    pub effective_at: DateTime<Utc>,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyConsent {
    pub document_key: String,
    pub version: String,
    pub accepted_at: DateTime<Utc>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyConsentCreateRequest {
    pub documents: Vec<LegalDocumentAcceptance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookiePreferences {
    pub necessary: bool,
    pub preferences: bool,
    pub analytics: bool,
    pub marketing: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CookiePreferencesUpdateRequest {
    pub preferences: bool,
    pub analytics: bool,
    pub marketing: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileUploadIntentRequest {
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub purpose: String,
    pub checksum_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileUploadIntent {
    pub file_id: Uuid,
    pub upload_url: String,
    pub expires_at: DateTime<Utc>,
    pub required_headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRecord {
    pub id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
    pub purpose: String,
    pub status: String,
    pub metadata_stripped: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDownload {
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminOverview {
    pub account_count: i64,
    pub active_account_count: i64,
    pub suspended_account_count: i64,
    pub deleted_account_count: i64,
    pub admin_account_count: i64,
    pub role_count: i64,
    pub active_session_count: i64,
    pub security_event_count: i64,
    pub audit_log_count: i64,
    pub privacy_request_count: i64,
    pub system_setting_count: i64,
    pub public_admin_bootstrap_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserSummary {
    pub id: Uuid,
    pub username: Option<String>,
    pub status: String,
    pub display_name: String,
    pub primary_email: String,
    pub primary_phone: Option<String>,
    pub roles: Vec<String>,
    pub role_assignments: Vec<AdminUserRoleAssignment>,
    pub scopes: Vec<String>,
    pub locale: String,
    pub timezone_name: String,
    pub default_currency: String,
    pub email_count: i32,
    pub phone_count: i32,
    pub avatar_file_id: Option<Uuid>,
    pub avatar_filename: Option<String>,
    pub profile_bio: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub suspended_until: Option<DateTime<Utc>>,
    pub security: UserSecuritySummary,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminUserCreateRequest {
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub display_name: String,
    pub primary_phone: Option<String>,
    pub role_codes: Option<Vec<String>>,
    pub role_assignments: Option<Vec<AdminRoleAssignmentRequest>>,
    pub account_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserCreateResponse {
    pub user: AdminUserSummary,
    pub initial_password: String,
    pub account_text: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminUserUpdateRequest {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub primary_email: Option<String>,
    pub primary_phone: Option<String>,
    pub role_codes: Option<Vec<String>>,
    pub role_assignments: Option<Vec<AdminRoleAssignmentRequest>>,
    pub account_status: Option<String>,
    pub require_password_change: Option<bool>,
    pub require_mfa_enrollment: Option<bool>,
    pub disable_login: Option<bool>,
    pub default_currency: Option<String>,
    pub locale: Option<String>,
    pub timezone_name: Option<String>,
    pub profile_bio: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminRoleAssignmentRequest {
    pub role_code: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserRoleAssignment {
    pub role_code: String,
    pub role_name: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminUserBulkActionRequest {
    pub account_ids: Vec<Uuid>,
    pub action: String,
    pub status: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSystemSetting {
    pub id: Uuid,
    pub key: String,
    pub scope: String,
    pub value_type: String,
    pub description: Option<String>,
    pub is_sensitive: bool,
    pub default_value: Value,
    pub value: Value,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by_account_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminSystemSettingUpdateRequest {
    pub value: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminInvitationCreateRequest {
    pub count: Option<i32>,
    pub code: Option<String>,
    pub email: Option<String>,
    pub role_codes: Option<Vec<String>>,
    pub max_uses: Option<i32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminInvitationCode {
    pub id: Uuid,
    pub code: String,
    pub email: Option<String>,
    pub role_codes: Vec<String>,
    pub max_uses: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminInvitationCreateResponse {
    pub invitations: Vec<AdminInvitationCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminInvitationSummary {
    pub id: Uuid,
    pub email: Option<String>,
    pub role_codes: Vec<String>,
    pub status: String,
    pub max_uses: i32,
    pub use_count: i32,
    pub remaining_uses: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by_account_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdminInvitationListQuery {
    pub status: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminInvitationRevokeRequest {
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountDeactivateRequest {
    pub current_password: String,
    pub reason: Option<String>,
    pub revoke_other_sessions: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailVerificationConfirmRequest {
    pub verification_token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailVerificationResendRequest {
    pub email: String,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailChangeRequestCreateRequest {
    pub new_email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: Uuid,
    pub is_current: bool,
    pub authenticated_aal: i32,
    pub device_label: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionBulkRevokeRequest {
    pub scope: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub id: Uuid,
    pub event_type: String,
    pub severity: String,
    pub summary: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_label: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminSecurityEvent {
    pub id: Uuid,
    pub account_id: Uuid,
    pub account_email: Option<String>,
    pub event_type: String,
    pub severity: String,
    pub summary: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_label: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecurityReportCreateRequest {
    pub category: String,
    pub description: String,
    pub related_event_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyRequest {
    pub id: Uuid,
    pub request_type: String,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub due_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub export_file_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyRequestCreateRequest {
    pub request_type: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleDefinition {
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub is_system_role: bool,
    pub requires_mfa: bool,
    pub permission_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDefinition {
    pub code: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleCreateRequest {
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub requires_mfa: Option<bool>,
    pub permission_codes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoleUpdateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub requires_mfa: Option<bool>,
    pub permission_codes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<Uuid>,
    pub actor_account_id: Option<Uuid>,
    pub summary: Option<String>,
    pub request_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PaginationQuery {
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SearchPaginationQuery {
    pub query: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserListQuery {
    pub query: Option<String>,
    pub status: Option<String>,
    pub role: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}
