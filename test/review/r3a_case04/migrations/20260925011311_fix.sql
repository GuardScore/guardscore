
create policy "users_insert_own" on public."users" for insert to authenticated with check ("id" = auth.uid());
