-- Fix team_members RLS to allow users to read their own rows
-- This is critical for allowing new members to see which teams they've been added to

drop policy if exists "team_members_can_read" on team_members;

-- Users can read their own team_members rows or rows from teams they're in
create policy "team_members_can_read" on team_members
  for select
  using (
    -- Users can always read their own rows
    user_id = auth.uid()
    OR
    -- Users can read rows from teams they're members of
    exists (
      select 1 from private.team_members_rows() tm
      where tm.team_id = team_members.team_id
      and tm.user_id = auth.uid()
    )
  );
