-- Create invitations table
create table invitations (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  token text not null unique default encode(gen_random_bytes(32), 'hex'),
  role text not null default 'member' check (role in ('owner', 'member')),
  invited_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamp with time zone default now(),
  accepted_at timestamp with time zone,
  accepted_by uuid references auth.users(id) on delete set null,
  expires_at timestamp with time zone default now() + interval '30 days',
  unique(team_id, email)
);

-- Create indexes
create index invitations_team_id_idx on invitations(team_id);
create index invitations_email_idx on invitations(email);
create index invitations_token_idx on invitations(token);
create index invitations_accepted_at_idx on invitations(accepted_at);

-- Enable RLS
alter table invitations enable row level security;

-- Invitations policies
create policy "Team owners can view team invitations"
  on invitations for select
  using (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid() and role = 'owner'
    )
  );

create policy "Team owners can create invitations"
  on invitations for insert
  with check (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid() and role = 'owner'
    )
    and invited_by = auth.uid()
  );

create policy "Users can view their own invitations"
  on invitations for select
  using (
    email = auth.jwt() ->> 'email'
    or
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid() and role = 'owner'
    )
  );

create policy "Anyone with valid token can accept invitation"
  on invitations for update
  using (
    -- Allow update if user's email matches and invitation not yet accepted
    email = auth.jwt() ->> 'email'
    and accepted_at is null
    and expires_at > now()
  )
  with check (
    -- Ensure accepted_by is set to current user and accepted_at is set
    accepted_by = auth.uid()
    and email = auth.jwt() ->> 'email'
  );

create policy "Team owners can delete pending invitations"
  on invitations for delete
  using (
    team_id in (
      select team_id from private.team_members_rows()
      where user_id = auth.uid() and role = 'owner'
    )
    and accepted_at is null
  );

-- Function to accept invitation and add user to team
create or replace function public.accept_invitation(invitation_token text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  inv record;
  new_member record;
begin
  -- Find the invitation
  select * into inv from invitations
  where token = invitation_token
  and accepted_at is null
  and expires_at > now();

  if inv is null then
    return json_build_object('success', false, 'error', 'Invalid or expired invitation');
  end if;

  if inv.email != auth.jwt() ->> 'email' then
    return json_build_object('success', false, 'error', 'This invitation is for a different email address');
  end if;

  -- Add user to team if not already a member
  if not exists (select 1 from team_members where team_id = inv.team_id and user_id = auth.uid()) then
    insert into team_members (team_id, user_id, role)
    values (inv.team_id, auth.uid(), inv.role);
  end if;

  -- Mark invitation as accepted
  update invitations
  set accepted_at = now(), accepted_by = auth.uid()
  where id = inv.id;

  select * into new_member from team_members
  where team_id = inv.team_id and user_id = auth.uid();

  return json_build_object(
    'success', true,
    'team_id', inv.team_id,
    'role', new_member.role,
    'message', 'Successfully joined team'
  );
end $$;

-- Function for team owners to create invitations
create or replace function public.invite_to_team(team_id uuid, email text, role text default 'member')
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  new_inv record;
  is_owner boolean;
begin
  -- Check if user is owner of the team
  select exists(
    select 1 from team_members
    where team_id = invite_to_team.team_id
    and user_id = auth.uid()
    and role = 'owner'
  ) into is_owner;

  if not is_owner then
    return json_build_object('success', false, 'error', 'Only team owners can invite members');
  end if;

  -- Create or update the invitation
  insert into invitations (team_id, email, invited_by, role)
  values (invite_to_team.team_id, email, auth.uid(), role)
  on conflict (team_id, email) do update
  set created_at = now(), invited_by = auth.uid(), accepted_at = null, expires_at = now() + interval '30 days'
  returning * into new_inv;

  return json_build_object(
    'success', true,
    'invitation_id', new_inv.id,
    'email', new_inv.email,
    'token', new_inv.token,
    'role', new_inv.role,
    'expires_at', new_inv.expires_at
  );
end $$;
