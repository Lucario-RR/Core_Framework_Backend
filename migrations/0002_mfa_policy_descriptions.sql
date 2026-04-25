update ops.setting_definition
set description = 'Mark newly created administrator accounts for MFA enrollment.',
    updated_at = now()
where key = 'auth.mfa.required_for_admins';

update ops.setting_definition
set description = 'Mark newly created accounts for MFA enrollment.',
    updated_at = now()
where key = 'auth.mfa.required_for_all_users';
