-- Create invitations table
create table invitations (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  token text not null unique,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  invited_by uuid not null references auth.users(id) on delete cascade,
  accepted_at timestamp with time zone,
  user_id uuid references auth.users(id) on delete cascade,
  created_at timestamp with time zone default now(),
  expires_at timestamp with time zone default (now() + interval '30 days'),
  unique(team_id, email)
);

-- Add indexes
create index idx_invitations_team on invitations(team_id);
create index idx_invitations_email on invitations(email);
create index idx_invitations_token on invitations(token);
create index idx_invitations_user on invitations(user_id);

-- Enable RLS
alter table invitations enable row level security;

-- RLS Policies for invitations
create policy "Team owners can see invitations"
  on invitations for select to authenticated
  using (
    exists (
      select 1 from teams
      where teams.id = invitations.team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Invited users can see their invitations"
  on invitations for select to authenticated
  using (
    invitations.email = (select email from auth.users where id = auth.uid())
    or invitations.user_id = auth.uid()
  );

create policy "Team owners can create invitations"
  on invitations for insert to authenticated
  with check (
    exists (
      select 1 from teams
      where teams.id = team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Team owners can update invitations"
  on invitations for update to authenticated
  using (
    exists (
      select 1 from teams
      where teams.id = invitations.team_id
      and teams.owner_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from teams
      where teams.id = invitations.team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Team owners can delete invitations"
  on invitations for delete to authenticated
  using (
    exists (
      select 1 from teams
      where teams.id = invitations.team_id
      and teams.owner_id = auth.uid()
    )
  );

-- Create function to generate secure tokens
create or replace function generate_invitation_token()
  returns text as $$
  select encode(gen_random_bytes(32), 'hex');
$$ language sql;

-- Create function to accept invitation
create or replace function accept_invitation(token_input text)
  returns json as $$
  declare
    invitation_record invitations%rowtype;
    team_record teams%rowtype;
    result json;
  begin
    -- Get invitation
    select * into invitation_record from invitations
    where token = token_input
    and accepted_at is null
    and expires_at > now();

    if not found then
      return json_build_object('success', false, 'error', 'Invalid or expired invitation');
    end if;

    -- Get team
    select * into team_record from teams where id = invitation_record.team_id;

    -- Add user to team
    insert into team_members (team_id, user_id, role)
    values (invitation_record.team_id, auth.uid(), invitation_record.role)
    on conflict (team_id, user_id) do nothing;

    -- Mark invitation as accepted
    update invitations
    set accepted_at = now(), user_id = auth.uid()
    where id = invitation_record.id;

    return json_build_object(
      'success', true,
      'team_id', team_record.id,
      'team_name', team_record.name
    );
  end;
$$ language plpgsql security definer;

-- Grant execute permission
revoke all on function accept_invitation(text) from public;
grant execute on function accept_invitation(text) to authenticated;
