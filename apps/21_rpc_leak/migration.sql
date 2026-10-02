-- Notes are owner-only, but a helper function (security definer) returns any
-- user's notes for whatever user id it is given.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  body text not null
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create or replace function public.get_user_notes(uid uuid) returns setof public.notes
  language sql stable security definer set search_path = public as $$
  select * from public.notes where user_id = uid;
$$;
-- Correctly scoped: returns only the caller's notes.
create or replace function public.get_my_notes() returns setof public.notes
  language sql stable security definer set search_path = public as $$
  select * from public.notes where user_id = auth.uid();
$$;
