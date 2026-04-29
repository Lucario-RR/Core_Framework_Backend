insert into iam.permission (id, code, name, description)
values
    ('11111111-1111-4111-8111-111111111119', 'admin:invitations:read', 'Read invitations', 'Read registration invitation metadata.'),
    ('11111111-1111-4111-8111-111111111120', 'admin:invitations:write', 'Write invitations', 'Create and revoke registration invitations.')
on conflict (code) do nothing;

insert into iam.role_permission (role_id, permission_id)
select r.id, p.id
from iam.role r
cross join iam.permission p
where r.code = 'admin'
  and p.code in ('admin:invitations:read', 'admin:invitations:write')
on conflict do nothing;

insert into iam.role_permission (role_id, permission_id)
select r.id, p.id
from iam.role r
cross join iam.permission p
where r.code = 'support'
  and p.code = 'admin:invitations:read'
on conflict do nothing;
