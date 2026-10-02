-- Fix infinite recursion in team_members RLS policies by using security-definer functions

create schema if not exists private;
grant usage on schema private to anon, authenticated;

-- Create security-definer function for team_members reads
create or replace function private.team_members_rows()
returns setof public.team_members
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select * from public.team_members
$$;

revoke all on function private.team_members_rows() from public;
grant execute on function private.team_members_rows() to anon, authenticated;

-- Drop existing policies on team_members
drop policy if exists "team_members_can_read" on team_members;
drop policy if exists "team_members_can_read_own" on team_members;
drop policy if exists "team_owners_can_manage" on team_members;
drop policy if exists "team_owners_can_remove" on team_members;

-- Recreate team_members policies using the security-definer function
create policy "team_members_can_read" on team_members
  for select
  using (
    exists (
      select 1 from private.team_members_rows() tm
      where tm.team_id = team_members.team_id
      and tm.user_id = auth.uid()
    )
  );

create policy "team_owners_can_manage" on team_members
  for insert
  with check (
    exists (
      select 1 from teams
      where teams.id = team_members.team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "team_owners_can_remove" on team_members
  for delete
  using (
    exists (
      select 1 from teams
      where teams.id = team_members.team_id
      and teams.owner_id = auth.uid()
    )
  );

-- Also need to fix the teams policies that reference team_members
drop policy if exists "users_can_read_own_teams" on teams;

create policy "users_can_read_own_teams" on teams
  for select
  using (
    owner_id = auth.uid()
    or exists (
      select 1 from private.team_members_rows() tm
      where tm.team_id = teams.id
      and tm.user_id = auth.uid()
    )
  );
