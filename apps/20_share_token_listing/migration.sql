-- "Share a note by link": the shared-note policy lets anyone list every shared
-- note and its token, so every link is effectively public.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  body text not null,
  share_token text unique
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "shared notes are public" on public.notes for select to anon, authenticated using (share_token is not null);
