-- Invitations table for team owners to invite members by email
create table invitations (
  id uuid primary key default uuid_generate_v4(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  invited_by uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'expired')),
  invitation_code text unique not null,
  created_at timestamp with time zone default now(),
  expires_at timestamp with time zone default (now() + interval '30 days'),
  accepted_at timestamp with time zone,
  unique(team_id, email)
);

-- Create indexes for faster lookups
create index invitations_team_id_idx on invitations(team_id);
create index invitations_email_idx on invitations(email);
create index invitations_invitation_code_idx on invitations(invitation_code);
create index invitations_status_idx on invitations(status);

-- Enable RLS
alter table invitations enable row level security;

-- RLS Policies for invitations
-- Only team owners can view invitations for their team
create policy "team_owners_can_view_invitations"
  on invitations for select
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = invitations.team_id
      and team_members.role = 'owner'
    )
  );

-- Only team owners can create invitations
create policy "team_owners_can_create_invitations"
  on invitations for insert
  with check (
    auth.uid() = invited_by and
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = invitations.team_id
      and team_members.role = 'owner'
    )
  );

-- Only team owners can update invitations (e.g., cancel pending ones)
create policy "team_owners_can_update_invitations"
  on invitations for update
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = invitations.team_id
      and team_members.role = 'owner'
    )
  );

-- Anyone can view a specific invitation if they have the correct email (to verify invitations)
-- This is checked via email matching, not exposed broadly
create policy "users_can_view_own_invitations"
  on invitations for select
  using (
    email = (
      select email from auth.users
      where auth.users.id = auth.uid()
    ) and status = 'pending'
  );

-- Function to generate invitation codes
create or replace function generate_invitation_code()
returns text as $$
  select upper(
    substring(md5(random()::text || clock_timestamp()::text), 1, 8)
  );
$$ language sql;

-- Function to accept an invitation and add user to team
create or replace function accept_invitation(invitation_code text)
returns json as $$
declare
  inv record;
  member_id uuid;
begin
  -- Find the invitation
  select * into inv from invitations
  where invitations.invitation_code = invitation_code
  and invitations.status = 'pending'
  and invitations.expires_at > now();

  if inv is null then
    return json_build_object('error', 'Invalid or expired invitation');
  end if;

  -- Check if user email matches
  if (select email from auth.users where auth.users.id = auth.uid()) != inv.email then
    return json_build_object('error', 'Email does not match invitation');
  end if;

  -- Add user to team if not already a member
  if not exists (
    select 1 from team_members
    where team_members.team_id = inv.team_id
    and team_members.user_id = auth.uid()
  ) then
    insert into team_members (team_id, user_id, role)
    values (inv.team_id, auth.uid(), 'member');
  end if;

  -- Update invitation status
  update invitations
  set status = 'accepted', accepted_at = now()
  where id = inv.id;

  return json_build_object('success', true, 'team_id', inv.team_id::text);
end;
$$ language plpgsql security definer;

-- Allow authenticated users to accept invitations
grant execute on function accept_invitation(text) to authenticated;

-- Function to send invitation (for backend/API use)
-- Note: In production, this would send actual emails
create or replace function send_team_invitation(team_id uuid, email text)
returns json as $$
declare
  owner_check uuid;
  inv_code text;
  new_invitation record;
begin
  -- Verify caller is a team owner
  select user_id into owner_check from team_members
  where team_members.team_id = send_team_invitation.team_id
  and team_members.user_id = auth.uid()
  and team_members.role = 'owner';

  if owner_check is null then
    return json_build_object('error', 'Only team owners can send invitations');
  end if;

  -- Generate unique invitation code
  inv_code := generate_invitation_code();
  while exists (select 1 from invitations where invitation_code = inv_code) loop
    inv_code := generate_invitation_code();
  end loop;

  -- Create invitation
  insert into invitations (team_id, email, invited_by, invitation_code)
  values (team_id, email, auth.uid(), inv_code)
  returning * into new_invitation;

  return json_build_object(
    'success', true,
    'invitation_code', new_invitation.invitation_code,
    'email', new_invitation.email,
    'expires_at', new_invitation.expires_at
  );
end;
$$ language plpgsql security definer;

-- Allow authenticated users to send invitations
grant execute on function send_team_invitation(uuid, text) to authenticated;
