-- Invitations table for email-based team invitations
create table invitations (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  invited_by uuid not null references auth.users(id),
  role text default 'member' check (role in ('member', 'admin')),
  status text default 'pending' check (status in ('pending', 'accepted', 'rejected')),
  accepted_at timestamp with time zone,
  created_at timestamp with time zone default now(),
  unique(team_id, email)
);

-- Enable RLS
alter table invitations enable row level security;

-- Invitations: Only team owners can view/create/manage
create policy "team_owners_can_view_invitations" on invitations
  for select using (
    team_id in (select id from teams where owner_id = auth.uid()) or
    email = auth.jwt() ->> 'email'
  );

create policy "team_owners_can_invite" on invitations
  for insert with check (
    team_id in (select id from teams where owner_id = auth.uid())
  );

create policy "team_owners_can_cancel_invitations" on invitations
  for delete using (
    team_id in (select id from teams where owner_id = auth.uid())
  );

create policy "invited_users_can_accept" on invitations
  for update using (
    email = auth.jwt() ->> 'email' or
    team_id in (select id from teams where owner_id = auth.uid())
  );

-- Indexes
create index idx_invitations_team on invitations(team_id);
create index idx_invitations_email on invitations(email);
create index idx_invitations_status on invitations(status);

-- Function to auto-accept pending invitations when user signs up
create or replace function auto_accept_pending_invitations()
returns trigger as $$
begin
  -- Accept all pending invitations for this email
  update invitations
  set status = 'accepted', accepted_at = now()
  where email = new.email and status = 'pending';

  -- Auto-add user to teams from accepted invitations
  insert into team_members (team_id, user_id, role)
  select team_id, new.id, role
  from invitations
  where email = new.email and status = 'accepted'
  on conflict do nothing;

  return new;
end;
$$ language plpgsql;

-- Trigger to auto-accept invitations on user creation
create trigger auto_accept_invitations_on_signup
  after insert on auth.users
  for each row
  execute function auto_accept_pending_invitations();
