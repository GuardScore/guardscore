-- Create invitations table for pending team member invites

create table invitations (
  id uuid primary key default uuid_generate_v4(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  role text default 'member',
  invited_by uuid not null references auth.users(id) on delete set null,
  created_at timestamptz default now(),
  expires_at timestamptz default now() + interval '7 days',
  accepted_at timestamptz,
  accepted_by_user_id uuid references auth.users(id) on delete set null,
  unique(team_id, email)
);

create index idx_invitations_team on invitations(team_id);
create index idx_invitations_email on invitations(email);
create index idx_invitations_accepted on invitations(accepted_at);

-- Enable RLS on invitations
alter table invitations enable row level security;

-- Team owners can see invitations for their team
create policy "team_owners_can_read_invitations" on invitations
  for select
  using (
    exists (
      select 1 from teams
      where teams.id = invitations.team_id
      and teams.owner_id = auth.uid()
    )
  );

-- Team members can see if they've been invited (after accepting they won't need to)
create policy "users_can_see_own_invitations" on invitations
  for select
  using (email = (select email from auth.users where id = auth.uid()));

-- Team owners can create invitations
create policy "team_owners_can_create_invitations" on invitations
  for insert
  with check (
    exists (
      select 1 from teams
      where teams.id = invitations.team_id
      and teams.owner_id = auth.uid()
    )
  );

-- Team owners can delete/rescind invitations
create policy "team_owners_can_delete_invitations" on invitations
  for delete
  using (
    exists (
      select 1 from teams
      where teams.id = invitations.team_id
      and teams.owner_id = auth.uid()
    )
  );

-- Users can accept their own invitations
create policy "users_can_accept_invitations" on invitations
  for update
  using (email = (select email from auth.users where id = auth.uid()))
  with check (email = (select email from auth.users where id = auth.uid()));

-- Create a function to accept an invitation
create or replace function public.accept_invitation(
  p_invitation_id uuid
)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  v_team_id uuid;
  v_role text;
  v_user_id uuid;
  v_email text;
begin
  v_user_id := auth.uid();

  if v_user_id is null then
    raise exception 'Unauthorized';
  end if;

  -- Get user's email
  select email into v_email from auth.users where id = v_user_id;

  -- Get invitation and verify it matches the user
  select team_id, role
  into v_team_id, v_role
  from invitations
  where id = p_invitation_id
  and email = v_email
  and accepted_at is null
  and expires_at > now();

  if v_team_id is null then
    raise exception 'Invitation not found, expired, or already accepted';
  end if;

  -- Check if already a member
  if exists(select 1 from team_members where team_id = v_team_id and user_id = v_user_id) then
    -- Just mark invitation as accepted
    update invitations
    set accepted_at = now(), accepted_by_user_id = v_user_id
    where id = p_invitation_id;
    return json_build_object('success', true, 'already_member', true);
  end if;

  -- Add as team member
  insert into team_members (team_id, user_id, role)
  values (v_team_id, v_user_id, v_role);

  -- Mark invitation as accepted
  update invitations
  set accepted_at = now(), accepted_by_user_id = v_user_id
  where id = p_invitation_id;

  return json_build_object('success', true, 'team_id', v_team_id);
end;
$$;

grant execute on function public.accept_invitation(uuid) to authenticated;
