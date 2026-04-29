alter table if exists iam.account_role
    add column if not exists expires_at timestamptz;

create index if not exists ix_iam_account_role_active
    on iam.account_role (account_id, expires_at);

alter table if exists iam.role
    add column if not exists updated_at timestamptz not null default now();
