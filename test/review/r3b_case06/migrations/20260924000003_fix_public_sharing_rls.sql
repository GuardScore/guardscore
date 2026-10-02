-- Drop conflicting policies (drop if exists to make it idempotent)
drop policy if exists "Public can view shared notes" on public.notes;
drop policy if exists "Anyone can view shared notes via token" on public.notes;

-- Create a public access policy that works for unauthenticated users
-- This policy allows ANYONE (authenticated or not) to read notes where share_token is not null
-- Key: we use USING clause which applies to both authenticated and unauthenticated users
create policy "Anyone can view shared notes"
  on public.notes
  for select
  using (share_token is not null);

-- Ensure both anon and authenticated roles have explicit select permission
grant select on public.notes to anon;
grant select on public.notes to authenticated;
grant select on public.notes to service_role;
