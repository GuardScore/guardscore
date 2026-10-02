-- Add sharing columns to notes table
alter table notes
  add column if not exists share_token text unique,
  add column if not exists is_shared boolean not null default false,
  add column if not exists shared_at timestamp with time zone;

-- Create index for faster share token lookups
create index if not exists idx_notes_share_token on notes(share_token) where is_shared = true;

-- Create private schema for secure shared note access
create schema if not exists private;
grant usage on schema private to anon, authenticated;

-- Create security-definer function in private schema to safely retrieve shared notes by token
-- This bypasses RLS when called from public schema
create or replace function private.get_shared_note(p_token text)
returns setof public.notes
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select * from public.notes
  where share_token = p_token and is_shared = true;
$$;

-- Grant execute on the private function to all users
grant execute on function private.get_shared_note(text) to anon, authenticated;

-- Also create a public wrapper that calls the private function
create or replace function public.get_shared_note(p_token text)
returns setof public.notes
language sql
stable
security invoker
as $$
  select * from private.get_shared_note(p_token);
$$;

grant execute on function public.get_shared_note(text) to anon, authenticated;
