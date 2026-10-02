-- The most common failure: a table created without row level security.
-- Supabase grants the public API roles access by default, so anyone can read it.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text not null
);
