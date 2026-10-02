-- Invitations table for email-based team invites
create table invitations (
  id uuid primary key default uuid_generate_v4(),
  team_id uuid not null references teams(id) on delete cascade,
  email text not null,
  role text not null check (role in ('owner', 'admin', 'member')),
  invited_by uuid not null,
  created_at timestamp with time zone default now(),
  expires_at timestamp with time zone default (now() + interval '7 days'),
  accepted_at timestamp with time zone,
  accepted_by uuid,
  unique(team_id, email)
);

-- Indexes for invitations
create index idx_invitations_team_id on invitations(team_id);
create index idx_invitations_email on invitations(email);
create index idx_invitations_expires_at on invitations(expires_at);

-- Row Level Security
alter table invitations enable row level security;

-- Users can view invitations sent to their email
create policy "Users can view their invitations"
  on invitations for select
  using (
    email = (select auth.jwt() ->> 'email')
    or team_id in (
      select id from teams
      where owner_id = auth.uid()
      or id in (select team_id from team_members where user_id = auth.uid())
    )
  );

-- Only team owner can create invitations
create policy "Only owner can create invitations"
  on invitations for insert
  with check (
    exists (
      select 1 from teams
      where id = team_id
      and owner_id = auth.uid()
    )
    and invited_by = auth.uid()
  );

-- Only team owner can update invitations (mark as accepted)
create policy "Only owner can update invitations"
  on invitations for update
  using (
    exists (
      select 1 from teams
      where id = team_id
      and owner_id = auth.uid()
    )
  );

-- Users can accept their own invitations
create policy "Users can accept their invitations"
  on invitations for update
  using (
    email = (select auth.jwt() ->> 'email')
    and accepted_at is null
  );

-- Only team owner can delete invitations
create policy "Only owner can delete invitations"
  on invitations for delete
  using (
    exists (
      select 1 from teams
      where id = team_id
      and owner_id = auth.uid()
    )
  );

-- Function to clean up expired invitations
create or replace function delete_expired_invitations()
returns void as $$
begin
  delete from invitations
  where expires_at < now()
  and accepted_at is null;
end;
$$ language plpgsql;
