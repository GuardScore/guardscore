-- "let me see everyone's notes": trusts profiles.role, which users can edit.
create policy "admins read all" on public.notes for select to authenticated
  using (exists (select 1 from public.profiles where id = auth.uid() and role = 'admin'));
