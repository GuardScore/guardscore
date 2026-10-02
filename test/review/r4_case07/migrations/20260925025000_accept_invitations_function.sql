-- Function to accept pending invitations for the current user
create or replace function accept_pending_invitations()
returns table(team_id uuid, team_name text, role text) as $$
declare
  user_email text;
begin
  -- Get current user's email
  user_email := auth.jwt() ->> 'email';

  if user_email is null then
    raise exception 'User not authenticated';
  end if;

  -- Accept all pending invitations for this email
  update invitations
  set status = 'accepted', accepted_at = now()
  where email = user_email and status = 'pending';

  -- Auto-add user to teams from accepted invitations
  insert into team_members (team_id, user_id, role)
  select team_id, auth.uid(), role
  from invitations
  where email = user_email and status = 'accepted'
  on conflict (team_id, user_id) do nothing;

  -- Return the teams the user joined
  return query
  select i.team_id, t.name, i.role
  from invitations i
  join teams t on t.id = i.team_id
  where i.email = user_email and i.status = 'accepted';
end;
$$ language plpgsql security definer;

-- Allow authenticated users to call this function
grant execute on function accept_pending_invitations() to authenticated;

-- Drop old trigger if it exists (it won't work on auth.users in Supabase)
drop trigger if exists auto_accept_invitations_on_signup on auth.users;
drop function if exists auto_accept_pending_invitations();
