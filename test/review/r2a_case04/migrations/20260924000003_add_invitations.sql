-- Create invitations table for email-based team invites
create table invitations (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  token text not null unique,
  created_by uuid not null references auth.users(id) on delete cascade,
  accepted_by uuid references auth.users(id) on delete set null,
  accepted_at timestamp with time zone,
  expires_at timestamp with time zone not null,
  created_at timestamp with time zone default now(),
  unique(team_id, email)
);

-- Create indexes for performance
create index idx_invitations_team_id on invitations(team_id);
create index idx_invitations_email on invitations(email);
create index idx_invitations_token on invitations(token);
create index idx_invitations_created_by on invitations(created_by);

-- Enable RLS
alter table invitations enable row level security;

-- Team owners can create invitations
create policy "Team owners can create invitations"
  on invitations for insert
  with check (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = invitations.team_id
    and tm.user_id = auth.uid()
    and tm.role = 'owner'
  ));

-- Team owners can view invitations for their teams
create policy "Team owners can view invitations"
  on invitations for select
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = invitations.team_id
    and tm.user_id = auth.uid()
    and tm.role = 'owner'
  ));

-- Users can accept pending invitations by token (no auth required to view/accept)
-- This allows unauthenticated users to see their invitation details
create policy "Users can accept invitations by token"
  on invitations for update
  using (
    accepted_at is null
    and expires_at > now()
    and token = current_setting('app.invitation_token', true)
  );

-- Team owners can delete/revoke invitations
create policy "Team owners can delete invitations"
  on invitations for delete
  using (exists (
    select 1 from private.team_members_rows() tm
    where tm.team_id = invitations.team_id
    and tm.user_id = auth.uid()
    and tm.role = 'owner'
  ));
