alter table if exists iam.account_phone
    add column if not exists is_login_enabled boolean not null default false;

create unique index if not exists uq_iam_account_phone_active_login
    on iam.account_phone (e164_phone_number)
    where deleted_at is null and is_login_enabled = true;

alter table if exists auth.registration_invite
    alter column expires_at drop not null;

alter table if exists auth.registration_invite
    add column if not exists max_uses integer not null default 1,
    add column if not exists use_count integer not null default 0,
    add column if not exists last_used_at timestamptz,
    add column if not exists revoked_at timestamptz;

create unique index if not exists uq_auth_registration_invite_code_hash
    on auth.registration_invite (invite_code_hash);

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'ck_auth_registration_invite_use_count'
    ) then
        alter table auth.registration_invite
            add constraint ck_auth_registration_invite_use_count
            check (max_uses > 0 and use_count >= 0 and use_count <= max_uses);
    end if;
end $$;

insert into ops.setting_definition (id, key, value_type, description, is_sensitive, default_value_json)
values (
    '33333333-3333-4333-8333-333333333323',
    'auth.password.policy',
    'json',
    'Password policy shared with clients for precheck and enforced by backend password writes.',
    false,
    '{
        "minLength": 12,
        "requireLetter": true,
        "requireNumber": true,
        "requireSpecial": false,
        "requireUppercase": false,
        "requireLowercase": false,
        "disallowUsername": true,
        "disallowEmail": true
    }'::jsonb
)
on conflict (key) do nothing;

insert into ops.system_setting (id, definition_id, scope, value_json)
select gen_random_uuid(), id, 'global', default_value_json
from ops.setting_definition
where key = 'auth.password.policy'
on conflict do nothing;
