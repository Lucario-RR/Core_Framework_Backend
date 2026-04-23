create extension if not exists pgcrypto;

create schema if not exists iam;
create schema if not exists auth;
create schema if not exists ops;
create schema if not exists privacy;
create schema if not exists file;

create table if not exists iam.account (
    id uuid primary key,
    public_handle varchar(80),
    status_code varchar(30) not null,
    created_by_account_id uuid references iam.account (id),
    activated_at timestamptz,
    last_login_at timestamptz,
    deleted_at timestamptz,
    row_version bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists uq_iam_account_public_handle on iam.account (public_handle) where public_handle is not null;

create table if not exists iam.account_profile (
    account_id uuid primary key references iam.account (id) on delete cascade,
    display_name varchar(160),
    locale varchar(20) not null default 'en-GB',
    timezone_name varchar(80) not null default 'Europe/London',
    region_code varchar(10),
    default_currency varchar(3) not null default 'GBP',
    profile_bio text,
    avatar_file_id uuid,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists iam.account_status_history (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    from_status_code varchar(30),
    to_status_code varchar(30) not null,
    reason_code varchar(50),
    reason_text text,
    changed_by_account_id uuid references iam.account (id),
    request_id varchar(80),
    changed_at timestamptz not null default now()
);

create index if not exists ix_iam_account_status_history_account_changed_at
    on iam.account_status_history (account_id, changed_at desc);

create table if not exists iam.account_restriction (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    restriction_type varchar(30) not null,
    status_code varchar(20) not null default 'active',
    reason_code varchar(50),
    reason_text text,
    starts_at timestamptz not null default now(),
    ends_at timestamptz,
    created_by_account_id uuid references iam.account (id),
    lifted_by_account_id uuid references iam.account (id),
    lifted_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists ix_iam_account_restriction_active
    on iam.account_restriction (account_id, restriction_type, status_code, ends_at);

create table if not exists iam.account_email (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    email varchar(320) not null,
    normalized_email varchar(320) not null,
    label varchar(30) not null,
    is_login_enabled boolean not null default true,
    is_primary_for_account boolean not null default false,
    verification_status varchar(20) not null default 'pending',
    verified_at timestamptz,
    reverification_required_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);

create unique index if not exists uq_iam_account_email_active_normalized
    on iam.account_email (normalized_email)
    where deleted_at is null and is_login_enabled = true;

create unique index if not exists uq_iam_account_email_primary_active
    on iam.account_email (account_id)
    where is_primary_for_account = true and deleted_at is null;

create index if not exists ix_iam_account_email_account_created_at
    on iam.account_email (account_id, created_at desc);

create table if not exists iam.account_phone (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    e164_phone_number varchar(20) not null,
    label varchar(30) not null,
    is_sms_enabled boolean not null default false,
    is_primary_for_account boolean not null default false,
    verification_status varchar(20) not null default 'pending',
    verified_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);

create unique index if not exists uq_iam_account_phone_primary_active
    on iam.account_phone (account_id)
    where is_primary_for_account = true and deleted_at is null;

create table if not exists iam.role (
    id uuid primary key,
    code varchar(40) not null unique,
    name varchar(80) not null,
    description text,
    is_system_role boolean not null default true,
    requires_mfa boolean not null default false,
    created_at timestamptz not null default now()
);

create table if not exists iam.permission (
    id uuid primary key,
    code varchar(80) not null unique,
    name varchar(120) not null,
    description text,
    created_at timestamptz not null default now()
);

create table if not exists iam.role_permission (
    role_id uuid not null references iam.role (id) on delete cascade,
    permission_id uuid not null references iam.permission (id) on delete cascade,
    granted_at timestamptz not null default now(),
    primary key (role_id, permission_id)
);

create table if not exists iam.account_role (
    account_id uuid not null references iam.account (id) on delete cascade,
    role_id uuid not null references iam.role (id) on delete cascade,
    granted_by_account_id uuid references iam.account (id),
    granted_at timestamptz not null default now(),
    primary key (account_id, role_id)
);

create table if not exists auth.authenticator (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    authenticator_type varchar(30) not null,
    usage_type varchar(30) not null,
    display_label varchar(120),
    status varchar(20) not null default 'pending',
    enrolled_at timestamptz not null default now(),
    confirmed_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz not null default now()
);

create unique index if not exists uq_auth_password_authenticator_active
    on auth.authenticator (account_id)
    where authenticator_type = 'PASSWORD' and revoked_at is null;

create table if not exists auth.password_credential (
    authenticator_id uuid primary key references auth.authenticator (id) on delete cascade,
    password_hash text not null,
    salt_value bytea not null,
    hash_algorithm varchar(40) not null default 'ARGON2ID',
    hash_parameters_json jsonb not null,
    password_version integer not null default 1,
    changed_at timestamptz not null default now(),
    must_rotate boolean not null default false,
    compromised_at timestamptz
);

create table if not exists auth.password_history (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    password_hash text not null,
    salt_value bytea not null,
    hash_algorithm varchar(40) not null,
    hash_parameters_json jsonb not null,
    password_version integer not null,
    valid_from timestamptz not null,
    valid_to timestamptz not null,
    stored_at timestamptz not null default now()
);

create index if not exists ix_auth_password_history_account_version
    on auth.password_history (account_id, password_version desc);

create table if not exists auth.email_verification_challenge (
    id uuid primary key,
    account_email_id uuid not null references iam.account_email (id) on delete cascade,
    purpose_code varchar(40) not null,
    challenge_hash text not null,
    delivery_channel varchar(20) not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    invalidated_at timestamptz,
    request_ip inet,
    request_user_agent text,
    attempt_count integer not null default 0,
    created_at timestamptz not null default now()
);

create table if not exists auth.phone_verification_challenge (
    id uuid primary key,
    account_phone_id uuid not null references iam.account_phone (id) on delete cascade,
    challenge_hash text not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    invalidated_at timestamptz,
    request_ip inet,
    request_user_agent text,
    attempt_count integer not null default 0,
    created_at timestamptz not null default now()
);

create table if not exists auth.account_email_change_request (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    old_account_email_id uuid not null references iam.account_email (id),
    new_email varchar(320) not null,
    new_normalized_email varchar(320) not null,
    status varchar(20) not null default 'pending',
    old_address_confirmed_at timestamptz,
    new_address_confirmed_at timestamptz,
    expires_at timestamptz not null,
    completed_at timestamptz,
    created_at timestamptz not null default now()
);

create table if not exists auth.password_reset_challenge (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    requested_email_id uuid references iam.account_email (id),
    password_version_at_issue integer not null,
    challenge_hash text not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    invalidated_at timestamptz,
    request_ip inet,
    request_user_agent text,
    attempt_count integer not null default 0,
    created_at timestamptz not null default now()
);

create table if not exists auth.session (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    session_token_hash text,
    refresh_token_hash text not null,
    authenticated_aal smallint not null default 1,
    remember_me boolean not null default false,
    user_agent text,
    ip_address inet,
    device_label varchar(120),
    device_fingerprint_hash char(64),
    created_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    idle_expires_at timestamptz not null,
    absolute_expires_at timestamptz not null,
    revoked_at timestamptz,
    revoke_reason_code varchar(40),
    check (absolute_expires_at >= idle_expires_at)
);

create index if not exists ix_auth_session_account_absolute
    on auth.session (account_id, absolute_expires_at desc);

create table if not exists auth.trusted_device (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    device_fingerprint_hash char(64) not null,
    device_label varchar(120),
    first_seen_at timestamptz not null default now(),
    last_seen_at timestamptz,
    trust_expires_at timestamptz,
    revoked_at timestamptz
);

create table if not exists auth.login_challenge (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    session_id uuid references auth.session (id),
    challenge_type varchar(40) not null,
    available_factors_json jsonb not null,
    details_json jsonb not null default '{}'::jsonb,
    expires_at timestamptz not null,
    completed_at timestamptz,
    created_at timestamptz not null default now()
);

create table if not exists auth.account_lockout (
    id uuid primary key,
    subject_type varchar(20) not null,
    subject_key_hash char(64) not null,
    failure_count integer not null default 0,
    locked_until timestamptz,
    last_failure_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists uq_auth_account_lockout_subject
    on auth.account_lockout (subject_type, subject_key_hash);

create table if not exists auth.totp_factor (
    authenticator_id uuid primary key references auth.authenticator (id) on delete cascade,
    secret_ciphertext bytea not null,
    key_reference varchar(120),
    otp_algorithm varchar(20) not null default 'SHA1',
    digits smallint not null default 6,
    period_seconds smallint not null default 30,
    issuer_label varchar(120),
    confirmed_at timestamptz,
    check (digits in (6, 8))
);

create table if not exists auth.recovery_code_set (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    code_count smallint not null,
    status varchar(20) not null default 'active',
    issued_at timestamptz not null default now(),
    replaced_by_set_id uuid references auth.recovery_code_set (id),
    revoked_at timestamptz
);

create table if not exists auth.recovery_code (
    id uuid primary key,
    recovery_code_set_id uuid not null references auth.recovery_code_set (id) on delete cascade,
    sequence_number smallint not null,
    code_hash text not null,
    salt_value bytea not null,
    hash_algorithm varchar(40) not null default 'SHA256',
    used_at timestamptz,
    created_at timestamptz not null default now(),
    unique (recovery_code_set_id, sequence_number)
);

create table if not exists auth.passkey_credential (
    authenticator_id uuid primary key references auth.authenticator (id) on delete cascade,
    rp_id varchar(255) not null,
    webauthn_user_handle bytea not null,
    credential_id text not null,
    public_key_cose bytea,
    client_data_json jsonb,
    aaguid uuid,
    sign_count bigint,
    transports_json jsonb,
    user_verification_policy varchar(30),
    unique (rp_id, credential_id)
);

create table if not exists auth.passkey_registration_challenge (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    display_name varchar(120),
    challenge_json jsonb not null,
    expires_at timestamptz not null,
    verified_at timestamptz,
    created_at timestamptz not null default now()
);

create table if not exists auth.passkey_authentication_challenge (
    id uuid primary key,
    account_id uuid references iam.account (id) on delete cascade,
    challenge_json jsonb not null,
    expires_at timestamptz not null,
    verified_at timestamptz,
    created_at timestamptz not null default now()
);

create table if not exists auth.sms_factor (
    authenticator_id uuid primary key references auth.authenticator (id) on delete cascade,
    account_phone_id uuid not null references iam.account_phone (id),
    confirmed_at timestamptz,
    revoked_at timestamptz
);

create table if not exists auth.registration_draft (
    id uuid primary key,
    email varchar(320),
    normalized_email varchar(320),
    profile_json jsonb not null default '{}'::jsonb,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create table if not exists auth.registration_invite (
    id uuid primary key,
    email varchar(320),
    normalized_email varchar(320),
    invite_code_hash text not null,
    status varchar(20) not null default 'active',
    role_codes_json jsonb not null default '[]'::jsonb,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_by_account_id uuid references iam.account (id),
    created_at timestamptz not null default now()
);

create table if not exists auth.registration_approval (
    id uuid primary key,
    account_id uuid references iam.account (id) on delete cascade,
    status varchar(20) not null default 'pending',
    requested_at timestamptz not null default now(),
    decided_at timestamptz,
    decided_by_account_id uuid references iam.account (id),
    reason_text text
);

create table if not exists auth.external_identity (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    provider_code varchar(40) not null,
    provider_subject varchar(320) not null,
    provider_email varchar(320),
    linked_at timestamptz not null default now(),
    last_login_at timestamptz,
    is_active boolean not null default true,
    unique (provider_code, provider_subject)
);

create table if not exists ops.setting_definition (
    id uuid primary key,
    key varchar(120) not null unique,
    value_type varchar(20) not null,
    description text,
    is_sensitive boolean not null default false,
    default_value_json jsonb not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists ops.system_setting (
    id uuid primary key,
    definition_id uuid not null references ops.setting_definition (id) on delete cascade,
    scope varchar(30) not null default 'global',
    account_id uuid references iam.account (id) on delete cascade,
    value_json jsonb not null,
    updated_at timestamptz not null default now(),
    updated_by_account_id uuid references iam.account (id)
);

create unique index if not exists uq_ops_system_setting_definition_scope_account
    on ops.system_setting (definition_id, scope, coalesce(account_id, '00000000-0000-0000-0000-000000000000'::uuid));

create table if not exists ops.account_setting (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    setting_key varchar(120) not null,
    value_json jsonb not null,
    updated_at timestamptz not null default now(),
    unique (account_id, setting_key)
);

create table if not exists ops.audit_log (
    id uuid primary key,
    actor_account_id uuid references iam.account (id),
    action varchar(120) not null,
    entity_type varchar(60) not null,
    entity_id uuid,
    summary text,
    details_json jsonb not null default '{}'::jsonb,
    request_id varchar(80),
    created_at timestamptz not null default now()
);

create index if not exists ix_ops_audit_log_entity_created_at
    on ops.audit_log (entity_type, entity_id, created_at desc);

create table if not exists ops.security_event (
    id uuid primary key,
    account_id uuid references iam.account (id) on delete cascade,
    event_type varchar(80) not null,
    severity varchar(20) not null,
    summary text,
    ip_address inet,
    user_agent text,
    device_label varchar(120),
    details_json jsonb not null default '{}'::jsonb,
    request_id varchar(80),
    created_at timestamptz not null default now()
);

create index if not exists ix_ops_security_event_account_created_at
    on ops.security_event (account_id, created_at desc);

create table if not exists ops.idempotency_key (
    id uuid primary key,
    scope_code varchar(80) not null,
    account_id uuid references iam.account (id) on delete cascade,
    key_hash char(64) not null,
    request_hash char(64),
    response_json jsonb,
    created_at timestamptz not null default now(),
    expires_at timestamptz
);

create unique index if not exists uq_ops_idempotency_scope_account_key
    on ops.idempotency_key (scope_code, coalesce(account_id, '00000000-0000-0000-0000-000000000000'::uuid), key_hash);

create table if not exists ops.notification (
    id uuid primary key,
    account_id uuid references iam.account (id) on delete cascade,
    template_code varchar(80) not null,
    channel_type varchar(20) not null,
    status varchar(20) not null default 'queued',
    subject varchar(255),
    body_json jsonb not null,
    created_at timestamptz not null default now()
);

create table if not exists ops.notification_delivery (
    id uuid primary key,
    notification_id uuid not null references ops.notification (id) on delete cascade,
    channel_type varchar(20) not null,
    status varchar(20) not null default 'queued',
    attempt_count integer not null default 0,
    response_json jsonb,
    last_attempt_at timestamptz,
    delivered_at timestamptz,
    created_at timestamptz not null default now()
);

create table if not exists ops.email_domain_rule (
    id uuid primary key,
    rule_type varchar(20) not null,
    domain varchar(255) not null,
    created_at timestamptz not null default now(),
    unique (rule_type, domain)
);

create table if not exists ops.security_report (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    category varchar(40) not null,
    description text not null,
    related_event_id uuid references ops.security_event (id),
    status varchar(20) not null default 'open',
    created_at timestamptz not null default now()
);

create table if not exists ops.notification_preference (
    id uuid primary key,
    account_id uuid not null references iam.account (id) on delete cascade,
    channel_type varchar(20) not null,
    preference_key varchar(80) not null,
    enabled boolean not null default true,
    updated_at timestamptz not null default now(),
    unique (account_id, channel_type, preference_key)
);

create table if not exists ops.admin_action_approval (
    id uuid primary key,
    action_code varchar(80) not null,
    entity_type varchar(60) not null,
    entity_id uuid,
    requested_by_account_id uuid not null references iam.account (id),
    status varchar(20) not null default 'pending',
    requested_at timestamptz not null default now(),
    decided_at timestamptz,
    decided_by_account_id uuid references iam.account (id),
    reason_text text
);

create table if not exists ops.admin_case (
    id uuid primary key,
    account_id uuid references iam.account (id),
    case_type varchar(40) not null,
    status varchar(20) not null default 'open',
    created_by_account_id uuid not null references iam.account (id),
    assigned_to_account_id uuid references iam.account (id),
    created_at timestamptz not null default now(),
    closed_at timestamptz
);

create table if not exists ops.admin_case_note (
    id uuid primary key,
    admin_case_id uuid not null references ops.admin_case (id) on delete cascade,
    author_account_id uuid not null references iam.account (id),
    note_body text not null,
    created_at timestamptz not null default now()
);

create table if not exists ops.admin_impersonation_session (
    id uuid primary key,
    admin_account_id uuid not null references iam.account (id),
    target_account_id uuid not null references iam.account (id),
    reason_text text not null,
    started_at timestamptz not null default now(),
    ended_at timestamptz
);

create table if not exists ops.outbox_event (
    id uuid primary key,
    event_type varchar(80) not null,
    aggregate_type varchar(60) not null,
    aggregate_id uuid,
    payload_json jsonb not null,
    delivery_status varchar(20) not null default 'pending',
    created_at timestamptz not null default now(),
    sent_at timestamptz
);

create table if not exists privacy.legal_document (
    id uuid primary key,
    document_key varchar(60) not null,
    title varchar(160) not null,
    version varchar(40) not null,
    effective_at timestamptz not null,
    url text not null,
    is_current boolean not null default true,
    created_at timestamptz not null default now(),
    unique (document_key, version)
);

create table if not exists privacy.retention_policy (
    id uuid primary key,
    entity_type varchar(60) not null unique,
    retain_for_days integer not null,
    action_after_retention varchar(20) not null,
    applies_after_field varchar(40) not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists privacy.data_subject_request (
    id uuid primary key,
    account_id uuid references iam.account (id) on delete cascade,
    request_type varchar(30) not null,
    status varchar(20) not null default 'open',
    verified_by_account_id uuid references iam.account (id),
    export_file_asset_id uuid,
    requested_at timestamptz not null default now(),
    due_at timestamptz,
    completed_at timestamptz,
    notes text
);

create table if not exists privacy.legal_hold (
    id uuid primary key,
    entity_type varchar(60) not null,
    entity_id uuid not null,
    reason text not null,
    placed_by_account_id uuid references iam.account (id),
    placed_at timestamptz not null default now(),
    released_at timestamptz
);

create table if not exists privacy.privacy_notice_version (
    id uuid primary key,
    notice_type varchar(30) not null,
    version_label varchar(40) not null,
    title varchar(160),
    url text,
    published_at timestamptz not null,
    retired_at timestamptz
);

create table if not exists privacy.consent_record (
    id uuid primary key,
    account_id uuid references iam.account (id) on delete cascade,
    anonymous_subject_token_hash char(64),
    purpose_code varchar(60) not null,
    notice_version_id uuid references privacy.privacy_notice_version (id),
    consent_status varchar(20) not null,
    captured_via varchar(20) not null,
    evidence_json jsonb,
    captured_at timestamptz not null default now(),
    withdrawn_at timestamptz
);

create table if not exists privacy.cookie_definition (
    id uuid primary key,
    cookie_name varchar(120) not null,
    provider_name varchar(120),
    cookie_category varchar(30) not null,
    is_strictly_necessary boolean not null,
    duration_seconds bigint,
    description text,
    created_at timestamptz not null default now(),
    retired_at timestamptz
);

create table if not exists privacy.cookie_consent (
    id uuid primary key,
    account_id uuid references iam.account (id) on delete cascade,
    anonymous_subject_token_hash char(64),
    notice_version_id uuid references privacy.privacy_notice_version (id),
    preferences_allowed boolean not null default false,
    analytics_allowed boolean not null default false,
    marketing_allowed boolean not null default false,
    captured_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    withdrawn_at timestamptz
);

create table if not exists file.storage_object (
    id uuid primary key,
    storage_provider varchar(30) not null,
    bucket_name varchar(120) not null,
    object_key text not null,
    checksum_sha256 char(64),
    size_bytes bigint not null,
    metadata_json jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    deleted_at timestamptz
);

create table if not exists file.file_asset (
    id uuid primary key,
    storage_object_id uuid not null references file.storage_object (id) on delete cascade,
    owner_account_id uuid references iam.account (id) on delete cascade,
    original_filename varchar(255) not null,
    content_type varchar(120) not null,
    size_bytes bigint not null,
    purpose_code varchar(40) not null,
    status varchar(20) not null default 'upload_pending',
    metadata_stripped boolean not null default false,
    classification_code varchar(40) not null default 'PRIVATE',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);

create table if not exists file.file_attachment (
    id uuid primary key,
    file_asset_id uuid not null references file.file_asset (id) on delete cascade,
    entity_type varchar(60) not null,
    entity_id uuid not null,
    attachment_role varchar(40) not null,
    created_at timestamptz not null default now()
);

alter table if exists iam.account_profile
    add constraint fk_iam_account_profile_avatar
    foreign key (avatar_file_id) references file.file_asset (id);

alter table if exists privacy.data_subject_request
    add constraint fk_privacy_request_export_file
    foreign key (export_file_asset_id) references file.file_asset (id);

insert into iam.permission (id, code, name, description)
values
    ('11111111-1111-4111-8111-111111111111', 'admin:users:read', 'Read users', 'Read user summaries and related account details.'),
    ('11111111-1111-4111-8111-111111111112', 'admin:users:write', 'Write users', 'Create and update accounts from the admin workspace.'),
    ('11111111-1111-4111-8111-111111111113', 'admin:security:read', 'Read security', 'Read sessions, security events, and audit logs.'),
    ('11111111-1111-4111-8111-111111111114', 'admin:security:write', 'Write security', 'Revoke sessions and verify or unverify contact methods.'),
    ('11111111-1111-4111-8111-111111111115', 'admin:settings:read', 'Read settings', 'Read global settings and overview metrics.'),
    ('11111111-1111-4111-8111-111111111116', 'admin:settings:write', 'Write settings', 'Update persisted settings.'),
    ('11111111-1111-4111-8111-111111111117', 'admin:roles:read', 'Read roles', 'Read role and permission definitions.'),
    ('11111111-1111-4111-8111-111111111118', 'admin:roles:write', 'Write roles', 'Manage role relationships.')
on conflict (code) do nothing;

insert into iam.role (id, code, name, description, is_system_role, requires_mfa)
values
    ('22222222-2222-4222-8222-222222222221', 'user', 'User', 'Standard end-user account.', true, false),
    ('22222222-2222-4222-8222-222222222222', 'admin', 'Administrator', 'Full administrative control of the reusable core.', true, true),
    ('22222222-2222-4222-8222-222222222223', 'support', 'Support', 'Operational read access for support workflows.', true, true)
on conflict (code) do nothing;

insert into iam.role_permission (role_id, permission_id)
select '22222222-2222-4222-8222-222222222222'::uuid, id from iam.permission
on conflict do nothing;

insert into iam.role_permission (role_id, permission_id)
select '22222222-2222-4222-8222-222222222223'::uuid, id
from iam.permission
where code in ('admin:users:read', 'admin:security:read', 'admin:settings:read', 'admin:roles:read')
on conflict do nothing;

insert into ops.setting_definition (id, key, value_type, description, is_sensitive, default_value_json)
values
    ('33333333-3333-4333-8333-333333333301', 'registration.enabled', 'boolean', 'Toggle public self-service registration.', false, 'true'::jsonb),
    ('33333333-3333-4333-8333-333333333302', 'registration.invite_only', 'boolean', 'Require invitation-driven registration.', false, 'false'::jsonb),
    ('33333333-3333-4333-8333-333333333303', 'registration.bootstrap_admin_enabled', 'boolean', 'Allow the bootstrap admin registration endpoint.', false, 'true'::jsonb),
    ('33333333-3333-4333-8333-333333333304', 'auth.email_verification.required', 'boolean', 'Require primary email verification for full activation.', false, 'true'::jsonb),
    ('33333333-3333-4333-8333-333333333305', 'auth.password.min_length', 'integer', 'Minimum allowed password length.', false, '12'::jsonb),
    ('33333333-3333-4333-8333-333333333306', 'auth.password.history_count', 'integer', 'Prevent reuse of the latest password versions.', false, '5'::jsonb),
    ('33333333-3333-4333-8333-333333333307', 'auth.password.reset_ttl_seconds', 'integer', 'Password reset challenge lifetime.', false, '3600'::jsonb),
    ('33333333-3333-4333-8333-333333333308', 'auth.email.verification_ttl_seconds', 'integer', 'Email verification challenge lifetime.', false, '86400'::jsonb),
    ('33333333-3333-4333-8333-333333333309', 'auth.mfa.required_for_admins', 'boolean', 'Require MFA for administrator accounts.', false, 'true'::jsonb),
    ('33333333-3333-4333-8333-333333333310', 'auth.mfa.required_for_all_users', 'boolean', 'Require MFA for all accounts.', false, 'false'::jsonb),
    ('33333333-3333-4333-8333-333333333311', 'auth.passkey.enabled', 'boolean', 'Allow passkey registration and login.', false, 'true'::jsonb),
    ('33333333-3333-4333-8333-333333333312', 'auth.session.idle_timeout_seconds', 'integer', 'Per-session idle timeout.', false, '7200'::jsonb),
    ('33333333-3333-4333-8333-333333333313', 'auth.session.absolute_timeout_seconds', 'integer', 'Maximum absolute session lifetime.', false, '2592000'::jsonb),
    ('33333333-3333-4333-8333-333333333314', 'auth.session.concurrent_limit', 'integer', 'Maximum concurrent sessions per account.', false, '10'::jsonb),
    ('33333333-3333-4333-8333-333333333315', 'auth.rate_limit.login_max_failures', 'integer', 'Maximum login failures before a lockout is applied.', false, '5'::jsonb),
    ('33333333-3333-4333-8333-333333333316', 'auth.rate_limit.login_lockout_seconds', 'integer', 'Temporary login lockout duration.', false, '900'::jsonb),
    ('33333333-3333-4333-8333-333333333317', 'auth.rate_limit.password_reset_max_requests', 'integer', 'Maximum password reset starts within the rolling window.', false, '5'::jsonb),
    ('33333333-3333-4333-8333-333333333318', 'auth.rate_limit.password_reset_window_seconds', 'integer', 'Rolling password reset rate-limit window.', false, '900'::jsonb),
    ('33333333-3333-4333-8333-333333333319', 'security.allowed_email_domains', 'json', 'Optional allow-list of registration domains.', false, '[]'::jsonb),
    ('33333333-3333-4333-8333-333333333320', 'security.blocked_email_domains', 'json', 'Optional deny-list of registration domains.', false, '[]'::jsonb),
    ('33333333-3333-4333-8333-333333333321', 'account.deletion.retention_days', 'integer', 'Retention window after soft deletion.', false, '30'::jsonb),
    ('33333333-3333-4333-8333-333333333322', 'maintenance.read_only', 'boolean', 'Toggle maintenance or read-only mode.', false, 'false'::jsonb)
on conflict (key) do nothing;

insert into ops.system_setting (id, definition_id, scope, value_json)
select gen_random_uuid(), id, 'global', default_value_json
from ops.setting_definition
on conflict do nothing;

insert into privacy.privacy_notice_version (id, notice_type, version_label, title, url, published_at)
values
    ('44444444-4444-4444-8444-444444444401', 'TERMS', '2026-04-01', 'Terms of Service', 'https://example.com/legal/terms-of-service-2026-04-01', '2026-04-01T00:00:00Z'),
    ('44444444-4444-4444-8444-444444444402', 'PRIVACY', '2026-04-01', 'Privacy Policy', 'https://example.com/legal/privacy-policy-2026-04-01', '2026-04-01T00:00:00Z'),
    ('44444444-4444-4444-8444-444444444403', 'COOKIE', '2026-04-01', 'Cookie Policy', 'https://example.com/legal/cookie-policy-2026-04-01', '2026-04-01T00:00:00Z')
on conflict (id) do nothing;

insert into privacy.legal_document (id, document_key, title, version, effective_at, url, is_current)
values
    ('55555555-5555-4555-8555-555555555501', 'terms_of_service', 'Terms of Service', '2026-04-01', '2026-04-01T00:00:00Z', 'https://example.com/legal/terms-of-service-2026-04-01', true),
    ('55555555-5555-4555-8555-555555555502', 'privacy_policy', 'Privacy Policy', '2026-04-01', '2026-04-01T00:00:00Z', 'https://example.com/legal/privacy-policy-2026-04-01', true),
    ('55555555-5555-4555-8555-555555555503', 'cookie_policy', 'Cookie Policy', '2026-04-01', '2026-04-01T00:00:00Z', 'https://example.com/legal/cookie-policy-2026-04-01', true)
on conflict (document_key, version) do nothing;

insert into privacy.retention_policy (id, entity_type, retain_for_days, action_after_retention, applies_after_field)
values
    ('66666666-6666-4666-8666-666666666601', 'account', 30, 'ANONYMIZE', 'deleted_at'),
    ('66666666-6666-4666-8666-666666666602', 'session', 30, 'DELETE', 'revoked_at'),
    ('66666666-6666-4666-8666-666666666603', 'security_event', 365, 'ARCHIVE', 'created_at'),
    ('66666666-6666-4666-8666-666666666604', 'audit_log', 365, 'ARCHIVE', 'created_at')
on conflict (entity_type) do nothing;

insert into privacy.cookie_definition (id, cookie_name, provider_name, cookie_category, is_strictly_necessary, duration_seconds, description)
values
    ('77777777-7777-4777-8777-777777777701', 'refresh_token', 'core_framework_backend', 'ESSENTIAL', true, 2592000, 'Session refresh cookie for signed-in users.'),
    ('77777777-7777-4777-8777-777777777702', 'csrf_token', 'core_framework_backend', 'ESSENTIAL', true, 2592000, 'Double-submit CSRF protection token.'),
    ('77777777-7777-4777-8777-777777777703', 'cookie_subject', 'core_framework_backend', 'PREFERENCES', false, 31536000, 'Anonymous browser identifier for cookie preference persistence.')
on conflict do nothing;
