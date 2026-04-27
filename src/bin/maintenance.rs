use std::{env, process::ExitCode};

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;

use core_framework_backend::{
    api::contracts::{LegalDocumentAcceptance, RegisterRequest},
    auth::{self, AuthContext},
    config::AppConfig,
    error::{AppError, AppResult},
    request_context::RequestContext,
    services::{auth as auth_service, shared, user as user_service},
    AppState, MIGRATOR,
};

#[tokio::main]
async fn main() -> ExitCode {
    dotenvy::dotenv().ok();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("maintenance error [{}]: {}", error.code, error.message);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> AppResult<()> {
    let command = parse_command()?;
    if matches!(command, Command::Help) {
        print_usage();
        return Ok(());
    }

    let config = AppConfig::from_env()?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    if command.run_migrations() {
        MIGRATOR.run(&pool).await?;
    }

    let state = AppState::new(pool, config);

    match command {
        Command::Help => Ok(()),
        Command::CreateAdmin(args) => {
            let admin = create_admin(&state, args).await?;
            print_created_admin(&admin);
            Ok(())
        }
        Command::ListUsers(args) => list_users(&state, args).await,
    }
}

enum Command {
    Help,
    CreateAdmin(CreateAdminArgs),
    ListUsers(ListUsersArgs),
}

impl Command {
    fn run_migrations(&self) -> bool {
        match self {
            Self::CreateAdmin(args) => args.run_migrations,
            Self::ListUsers(args) => args.run_migrations,
            Self::Help => false,
        }
    }
}

struct CreateAdminArgs {
    email: String,
    password: String,
    display_name: String,
    primary_phone: Option<String>,
    run_migrations: bool,
    verify_email: bool,
    enroll_totp: bool,
    require_password_change: bool,
}

struct ListUsersArgs {
    limit: i64,
    run_migrations: bool,
}

struct CreatedAdmin {
    account_id: Uuid,
    email: String,
    display_name: String,
    roles: Vec<String>,
    email_verified: bool,
    mfa: Option<MfaEnrollment>,
}

struct MfaEnrollment {
    secret_base32: String,
    otpauth_uri: String,
    recovery_codes: Vec<String>,
}

fn parse_command() -> AppResult<Command> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };

    match command {
        "help" | "--help" | "-h" => Ok(Command::Help),
        "create-admin" => parse_create_admin_args(&args[1..]),
        "list-users" => parse_list_users_args(&args[1..]),
        _ => Err(AppError::validation(format!(
            "unknown maintenance command: {command}"
        ))),
    }
}

fn parse_create_admin_args(args: &[String]) -> AppResult<Command> {
    let mut email = None;
    let mut password = env::var("MAINTENANCE_ADMIN_PASSWORD").ok();
    let mut display_name = None;
    let mut primary_phone = None;
    let mut run_migrations = true;
    let mut verify_email = true;
    let mut enroll_totp = true;
    let mut require_password_change = false;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--email" => email = Some(next_value(args, &mut index, "--email")?),
            "--password" => password = Some(next_value(args, &mut index, "--password")?),
            "--display-name" => {
                display_name = Some(next_value(args, &mut index, "--display-name")?)
            }
            "--phone" => primary_phone = Some(next_value(args, &mut index, "--phone")?),
            "--no-migrations" => run_migrations = false,
            "--leave-email-pending" => verify_email = false,
            "--no-totp" => enroll_totp = false,
            "--require-password-change" => require_password_change = true,
            "--help" | "-h" => return Ok(Command::Help),
            flag => return Err(AppError::validation(format!("unknown flag: {flag}"))),
        }
        index += 1;
    }

    let email = required_arg(email, "--email")?;
    let password = required_arg(password, "--password or MAINTENANCE_ADMIN_PASSWORD")?;
    let display_name = display_name.unwrap_or_else(|| "Maintenance Admin".to_string());

    Ok(Command::CreateAdmin(CreateAdminArgs {
        email,
        password,
        display_name,
        primary_phone,
        run_migrations,
        verify_email,
        enroll_totp,
        require_password_change,
    }))
}

fn parse_list_users_args(args: &[String]) -> AppResult<Command> {
    let mut limit = 20_i64;
    let mut run_migrations = false;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--limit" => {
                let raw = next_value(args, &mut index, "--limit")?;
                limit = raw.parse::<i64>().map_err(|error| {
                    AppError::validation(format!("--limit must be an integer: {error}"))
                })?;
            }
            "--migrate" => run_migrations = true,
            "--help" | "-h" => return Ok(Command::Help),
            flag => return Err(AppError::validation(format!("unknown flag: {flag}"))),
        }
        index += 1;
    }

    if !(1..=100).contains(&limit) {
        return Err(AppError::validation("--limit must be between 1 and 100"));
    }

    Ok(Command::ListUsers(ListUsersArgs {
        limit,
        run_migrations,
    }))
}

fn next_value(args: &[String], index: &mut usize, flag: &str) -> AppResult<String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| AppError::validation(format!("{flag} requires a value")))
}

fn required_arg(value: Option<String>, label: &str) -> AppResult<String> {
    value
        .filter(|candidate| !candidate.trim().is_empty())
        .ok_or_else(|| AppError::validation(format!("missing required argument {label}")))
}

async fn create_admin(state: &AppState, args: CreateAdminArgs) -> AppResult<CreatedAdmin> {
    let context = RequestContext {
        request_id: format!("maintenance_{}", Uuid::new_v4().simple()),
        ip_address: None,
        user_agent: Some("maintenance-tool".to_string()),
    };
    let legal_documents = current_legal_documents(&state.pool).await?;
    let request = RegisterRequest {
        username: None,
        email: args.email.clone(),
        password: args.password,
        display_name: args.display_name.clone(),
        primary_phone: args.primary_phone,
        invitation_code: None,
        accepted_legal_documents: legal_documents,
    };

    let created = auth_service::create_local_account(
        &state.pool,
        &context,
        request,
        vec!["user".to_string(), "admin".to_string()],
        None,
        Some("active".to_string()),
        None,
        args.require_password_change,
    )
    .await?;

    if args.verify_email {
        verify_primary_email(&state.pool, created.account_id).await?;
    }

    let mfa = if args.enroll_totp {
        Some(enroll_totp(state, created.account_id).await?)
    } else {
        None
    };

    let summary = shared::load_admin_user_summary(&state.pool, created.account_id).await?;
    shared::record_audit_log(
        &state.pool,
        None,
        "maintenance.admin.created",
        "account",
        Some(created.account_id),
        Some("Maintenance tool created administrator account.".to_string()),
        json!({
            "email": summary.primary_email,
            "emailVerified": args.verify_email,
            "totpEnrolled": args.enroll_totp,
            "requirePasswordChange": args.require_password_change
        }),
        Some(&context.request_id),
    )
    .await?;

    Ok(CreatedAdmin {
        account_id: summary.id,
        email: summary.primary_email,
        display_name: summary.display_name,
        roles: summary.roles,
        email_verified: summary.security.primary_email_verified,
        mfa,
    })
}

async fn current_legal_documents(pool: &PgPool) -> AppResult<Vec<LegalDocumentAcceptance>> {
    let rows = sqlx::query(
        r#"
        select document_key, version
        from privacy.legal_document
        where is_current = true
        order by document_key
        "#,
    )
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Err(AppError::conflict(
            "no current legal documents were found; run migrations before creating accounts",
        ));
    }

    rows.into_iter()
        .map(|row| {
            Ok(LegalDocumentAcceptance {
                document_key: row.try_get("document_key")?,
                version: row.try_get("version")?,
            })
        })
        .collect()
}

async fn verify_primary_email(pool: &PgPool, account_id: Uuid) -> AppResult<()> {
    let affected = sqlx::query(
        r#"
        update iam.account_email
        set verification_status = 'verified',
            verified_at = now(),
            updated_at = now()
        where account_id = $1
          and is_primary_for_account = true
          and deleted_at is null
        "#,
    )
    .bind(account_id)
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::not_found("primary email was not found"));
    }

    sqlx::query(
        r#"
        update auth.email_verification_challenge
        set consumed_at = coalesce(consumed_at, now())
        where account_email_id in (
            select id
            from iam.account_email
            where account_id = $1
              and is_primary_for_account = true
              and deleted_at is null
        )
          and consumed_at is null
          and invalidated_at is null
        "#,
    )
    .bind(account_id)
    .execute(pool)
    .await?;

    Ok(())
}

async fn enroll_totp(state: &AppState, account_id: Uuid) -> AppResult<MfaEnrollment> {
    let email = sqlx::query_scalar::<_, String>(
        r#"
        select email
        from iam.account_email
        where account_id = $1
          and is_primary_for_account = true
          and deleted_at is null
        limit 1
        "#,
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;
    let secret = auth::generate_totp_secret();
    let secret_base32 = auth::encode_totp_secret(&secret);
    let otpauth_uri = auth::build_otpauth_uri(&state.config.totp_issuer, &email, &secret_base32);
    let authenticator_id = Uuid::new_v4();

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        r#"
        insert into auth.authenticator (
            id, account_id, authenticator_type, usage_type, display_label, status,
            enrolled_at, confirmed_at, created_at
        )
        values (
            $1, $2, 'TOTP', 'MFA', 'Maintenance bootstrap authenticator', 'active',
            now(), now(), now()
        )
        "#,
    )
    .bind(authenticator_id)
    .bind(account_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        insert into auth.totp_factor (
            authenticator_id, secret_ciphertext, otp_algorithm, digits, period_seconds,
            issuer_label, confirmed_at
        )
        values ($1, $2, 'SHA1', 6, 30, $3, now())
        "#,
    )
    .bind(authenticator_id)
    .bind(secret)
    .bind(&state.config.totp_issuer)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let recovery_codes = user_service::rotate_recovery_codes(
        state,
        &AuthContext {
            account_id,
            session_id: Uuid::new_v4(),
            roles: vec!["admin".to_string()],
            scopes: Vec::new(),
        },
    )
    .await?
    .codes;

    Ok(MfaEnrollment {
        secret_base32,
        otpauth_uri,
        recovery_codes,
    })
}

async fn list_users(state: &AppState, args: ListUsersArgs) -> AppResult<()> {
    let rows = sqlx::query(
        r#"
        select
            a.id,
            a.status_code,
            a.created_at,
            p.display_name,
            coalesce(ae.email, '') as email,
            coalesce(string_agg(r.code, ',' order by r.code), '') as roles
        from iam.account a
        join iam.account_profile p on p.account_id = a.id
        left join iam.account_email ae
          on ae.account_id = a.id
         and ae.is_primary_for_account = true
         and ae.deleted_at is null
        left join iam.account_role ar on ar.account_id = a.id
        left join iam.role r on r.id = ar.role_id
        group by a.id, a.status_code, a.created_at, p.display_name, ae.email
        order by a.created_at desc
        limit $1
        "#,
    )
    .bind(args.limit)
    .fetch_all(&state.pool)
    .await?;

    println!("Recent users:");
    println!("id | email | status | roles | display_name | created_at");
    for row in rows {
        let id: Uuid = row.try_get("id")?;
        let email: String = row.try_get("email")?;
        let status: String = row.try_get("status_code")?;
        let roles: String = row.try_get("roles")?;
        let display_name: String = row.try_get("display_name")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        println!("{id} | {email} | {status} | {roles} | {display_name} | {created_at}");
    }
    Ok(())
}

fn print_created_admin(admin: &CreatedAdmin) {
    println!("Created administrator account");
    println!("Account ID: {}", admin.account_id);
    println!("Email: {}", admin.email);
    println!("Display name: {}", admin.display_name);
    println!("Roles: {}", admin.roles.join(", "));
    println!("Primary email verified: {}", admin.email_verified);

    if let Some(mfa) = admin.mfa.as_ref() {
        println!();
        println!("TOTP MFA was enrolled for this account.");
        println!("Add this secret to an authenticator app:");
        println!("{}", mfa.secret_base32);
        println!();
        println!("otpauth URI:");
        println!("{}", mfa.otpauth_uri);
        println!();
        println!("Recovery codes:");
        for code in &mfa.recovery_codes {
            println!("{}", code);
        }
    } else {
        println!();
        println!(
            "TOTP MFA was not enrolled. Login is not blocked solely by MFA policy; clients should use user.security.mfaRequired and user.security.totpEnabled to show a skippable enrollment prompt."
        );
    }
}

fn print_usage() {
    println!(
        r#"Maintenance tool

Commands:
  create-admin --email <email> --display-name <name> [--password <password>]
  list-users [--limit <1-100>]

create-admin options:
  --email <email>             Email used to log in.
  --password <password>       Initial password. You can use MAINTENANCE_ADMIN_PASSWORD instead.
  --display-name <name>       Display name for the account.
  --phone <e164>              Optional primary phone number.
  --no-migrations             Do not run SQL migrations before creating the account.
  --leave-email-pending       Leave the primary email unverified.
  --no-totp                   Do not enrol bootstrap TOTP MFA.
  --require-password-change   Mark the password for rotation after login.

list-users options:
  --limit <1-100>             Number of recent users to print. Default: 20.
  --migrate                   Run SQL migrations before listing users.
"#
    );
}
