-- Create invitations table for pending team invites
create table invitations (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  token text not null unique,
  role text not null default 'member' check (role in ('owner', 'member')),
  invited_by uuid not null references auth.users(id) on delete cascade,
  accepted_by uuid references auth.users(id) on delete set null,
  created_at timestamptz default now(),
  expires_at timestamptz default now() + interval '7 days',
  accepted_at timestamptz,
  unique(team_id, email)
);

-- Indexes for performance
create index idx_invitations_team on invitations(team_id);
create index idx_invitations_email on invitations(email);
create index idx_invitations_token on invitations(token);

-- Enable RLS
alter table invitations enable row level security;

-- RLS Policies for invitations

-- Team members can view invitations for their team
create policy "Team members can view team invitations"
  on invitations for select
  using (
    auth.uid() in (
      select user_id from team_members
      where team_id = invitations.team_id
    )
  );

-- Only owners can create invitations
create policy "Only owners can create invitations"
  on invitations for insert
  with check (
    auth.uid() in (
      select user_id from team_members
      where team_id = invitations.team_id and role = 'owner'
    )
    and auth.uid() = invited_by
  );

-- Only owners can update/delete invitations
create policy "Only owners can update invitations"
  on invitations for update
  using (
    auth.uid() in (
      select user_id from team_members
      where team_id = invitations.team_id and role = 'owner'
    )
  );

create policy "Only owners can delete invitations"
  on invitations for delete
  using (
    auth.uid() in (
      select user_id from team_members
      where team_id = invitations.team_id and role = 'owner'
    )
  );

-- Function to accept an invitation and add user to team
create or replace function public.accept_invitation(invitation_token text)
returns json language plpgsql security definer set search_path = public as $$
declare
  inv record;
  new_member_id uuid;
begin
  -- Find the invitation
  select * into inv from invitations where token = invitation_token;

  if inv is null then
    return json_build_object('success', false, 'error', 'Invitation not found');
  end if;

  if inv.expires_at < now() then
    return json_build_object('success', false, 'error', 'Invitation has expired');
  end if;

  if inv.accepted_at is not null then
    return json_build_object('success', false, 'error', 'Invitation already accepted');
  end if;

  -- Get the current user ID
  new_member_id := auth.uid();
  if new_member_id is null then
    return json_build_object('success', false, 'error', 'User not authenticated');
  end if;

  -- Check if user already in team
  if exists (select 1 from team_members where team_id = inv.team_id and user_id = new_member_id) then
    return json_build_object('success', false, 'error', 'User already in team');
  end if;

  -- Add user to team
  insert into team_members (team_id, user_id, role)
  values (inv.team_id, new_member_id, inv.role);

  -- Mark invitation as accepted
  update invitations
  set accepted_by = new_member_id, accepted_at = now()
  where id = inv.id;

  return json_build_object('success', true, 'team_id', inv.team_id);
end $$;
