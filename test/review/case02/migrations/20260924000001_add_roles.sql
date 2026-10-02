-- Add user_id to teams for tracking owner
alter table teams add column owner_id uuid;

-- Update team_members table to ensure unique constraint
-- (already has unique on team_id, user_id from init)

-- Add index for faster role queries
create index idx_team_members_role on team_members(role);

-- Add a view to get team members with their info
create view team_members_view as
select
  tm.id,
  tm.team_id,
  tm.user_id,
  tm.role,
  tm.created_at
from team_members tm;

-- Add helper function to check if user is team owner
create or replace function is_team_owner(team_id uuid, user_id uuid)
returns boolean as $$
select exists(
  select 1 from team_members
  where team_id = team_id and user_id = user_id and role = 'owner'
)
$$ language sql;

-- Add helper function to check if user is team member
create or replace function is_team_member(team_id uuid, user_id uuid)
returns boolean as $$
select exists(
  select 1 from team_members
  where team_id = team_id and user_id = user_id
)
$$ language sql;
