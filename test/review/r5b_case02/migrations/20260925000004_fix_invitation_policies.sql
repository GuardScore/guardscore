-- Drop and recreate invitation policies with correct auth method
drop policy "Invited users can see their invitations" on invitations;

create policy "Invited users can see their invitations"
  on invitations for select to authenticated
  using (
    invitations.email = (auth.jwt() ->> 'email')
    or invitations.user_id = auth.uid()
  );
