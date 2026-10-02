-- Create a function to accept an invitation and add the user to the team
create or replace function public.accept_invitation(invitation_token text)
returns json
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  v_invitation record;
  v_team_member record;
begin
  -- Get the invitation
  select * into v_invitation from invitations
  where token = invitation_token
  and accepted_at is null
  and expires_at > now();

  if v_invitation is null then
    return json_build_object('error', 'Invitation not found or expired');
  end if;

  -- Add user to team_members as a member
  insert into team_members (team_id, user_id, role, created_at)
  values (v_invitation.team_id, auth.uid(), 'member', now())
  on conflict (team_id, user_id) do nothing;

  -- Mark invitation as accepted
  update invitations
  set accepted_by = auth.uid(), accepted_at = now()
  where id = v_invitation.id;

  return json_build_object(
    'success', true,
    'team_id', v_invitation.team_id,
    'message', 'Successfully joined the team'
  );
end;
$$;

-- Allow authenticated users to call this function
grant execute on function public.accept_invitation(text) to authenticated;

-- Also allow anonymous users to call it (they'll authenticate in the process)
grant execute on function public.accept_invitation(text) to anon;
