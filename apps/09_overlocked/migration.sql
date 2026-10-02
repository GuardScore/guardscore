-- Safe but broken: RLS on with no policies blocks the app's own users.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text not null
);
alter table public.notes enable row level security;
