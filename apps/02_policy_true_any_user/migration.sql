create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text not null
);
alter table public.notes enable row level security;
-- The CVE-2025-48757 pattern: RLS is on and a policy exists, so existence checks pass,
-- but the policy lets any logged-in user see everyone's rows.
create policy "authenticated can read" on public.notes for select to authenticated using (true);
create policy "authenticated can insert" on public.notes for insert to authenticated with check (user_id = auth.uid());
create policy "owner can update" on public.notes for update to authenticated using (user_id = auth.uid());
