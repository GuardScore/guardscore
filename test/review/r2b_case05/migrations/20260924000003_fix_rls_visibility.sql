-- Fix RLS policies to ensure newly added members can immediately see their team's data

-- Drop and recreate teams select policy with explicit join for better reliability
drop policy if exists "Users can view teams they belong to" on teams;

create policy "Users can view teams they belong to"
  on teams for select
  using (
    owner_id = auth.uid()
    or exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
    )
  );

-- Ensure projects policy is optimized
drop policy if exists "Team members can view projects" on projects;

create policy "Team members can view projects"
  on projects for select
  using (
    exists (
      select 1 from team_members
      where team_members.team_id = projects.team_id
      and team_members.user_id = auth.uid()
    )
    or exists (
      select 1 from teams
      where teams.id = projects.team_id
      and teams.owner_id = auth.uid()
    )
  );

-- Ensure tasks policy is optimized
drop policy if exists "Team members can view tasks" on tasks;

create policy "Team members can view tasks"
  on tasks for select
  using (
    exists (
      select 1 from projects
      inner join team_members on team_members.team_id = projects.team_id
      where projects.id = tasks.project_id
      and team_members.user_id = auth.uid()
    )
    or exists (
      select 1 from projects
      inner join teams on teams.id = projects.team_id
      where projects.id = tasks.project_id
      and teams.owner_id = auth.uid()
    )
  );

-- Create helper function to verify user's team access
create or replace function get_user_accessible_teams()
returns setof uuid as $$
  select distinct team_id from team_members where user_id = auth.uid()
  union
  select id from teams where owner_id = auth.uid()
$$ language sql stable;

-- Create index to speed up team_members lookups
create index if not exists idx_team_members_user_id_team_id
  on team_members(user_id, team_id);
