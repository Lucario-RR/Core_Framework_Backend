drop index if exists uq_iam_account_public_handle_ci;

create unique index if not exists uq_iam_account_public_handle_ci
    on iam.account (lower(public_handle))
    where deleted_at is null;
