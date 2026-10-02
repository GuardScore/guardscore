-- Add email field to team_members
alter table team_members add column email text;

-- Create invitations table
create table invitations (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  code text not null unique,
  role text default 'member',
  created_by uuid,
  created_at timestamp with time zone default now(),
  expires_at timestamp with time zone default (now() + interval '30 days'),
  accepted_at timestamp with time zone,
  unique(team_id, email)
);

-- Create index for faster invitation lookups
create index idx_invitations_code on invitations(code);
create index idx_invitations_team_id on invitations(team_id);
create index idx_invitations_email on invitations(email);
create index idx_invitations_accepted on invitations(accepted_at);
