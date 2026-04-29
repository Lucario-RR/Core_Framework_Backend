alter table if exists iam.account
    add column if not exists username_changed_at timestamptz;

with missing_username as (
    select
        a.id,
        case
            when length(base_username) >= 3 then left(base_username, 80)
            else 'user-' || left(a.id::text, 8)
        end as base_username
    from iam.account a
    join iam.account_profile p on p.account_id = a.id
    left join iam.account_email ae
      on ae.account_id = a.id
     and ae.is_primary_for_account = true
     and ae.deleted_at is null
    cross join lateral (
        select regexp_replace(
            regexp_replace(
                lower(coalesce(
                    nullif(trim(a.public_handle), ''),
                    nullif(trim(p.display_name), ''),
                    nullif(split_part(ae.email, '@', 1), ''),
                    'user-' || left(a.id::text, 8)
                )),
                '[^a-z0-9._-]+',
                '-',
                'g'
            ),
            '(^[-._]+|[-._]+$)',
            '',
            'g'
        ) as base_username
    ) candidate
    where a.public_handle is null
       or trim(a.public_handle) = ''
),
ranked_username as (
    select
        id,
        base_username,
        count(*) over (partition by base_username) as candidate_count
    from missing_username
)
update iam.account a
set public_handle = case
        when ranked.candidate_count = 1
         and not exists (
            select 1
            from iam.account existing
            where existing.id <> a.id
              and existing.public_handle is not null
              and lower(existing.public_handle) = ranked.base_username
         ) then ranked.base_username
        else left(ranked.base_username, 71) || '-' || left(a.id::text, 8)
    end,
    updated_at = now()
from ranked_username ranked
where a.id = ranked.id;

update iam.account
set public_handle = lower(public_handle)
where public_handle is not null
  and public_handle <> lower(public_handle);

drop index if exists uq_iam_account_public_handle;

create unique index if not exists uq_iam_account_public_handle_ci
    on iam.account (lower(public_handle));

alter table if exists iam.account
    alter column public_handle set not null;

alter table if exists iam.role
    add column if not exists deleted_at timestamptz;

insert into ops.setting_definition (id, key, value_type, description, is_sensitive, default_value_json)
values
    ('33333333-3333-4333-8333-333333333324', 'account.username.change_cooldown_seconds', 'integer', 'Minimum seconds before a user can change their username again. Use 0 to allow immediate changes.', false, '2592000'::jsonb)
on conflict (key) do nothing;

insert into ops.system_setting (id, definition_id, scope, value_json)
select gen_random_uuid(), id, 'global', default_value_json
from ops.setting_definition
where key = 'account.username.change_cooldown_seconds'
on conflict do nothing;
