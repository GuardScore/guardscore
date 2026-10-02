-- Ensure the get_shared_note function exists and is properly granted to anonymous users
-- This is a safeguard in case the previous migration didn't apply correctly

create or replace function public.get_shared_note(p_public_id text)
returns table (
  id uuid,
  user_id uuid,
  title text,
  content text,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  is_public boolean,
  public_id text
)
language sql
stable
security definer
set search_path = public
as $$
  select id, user_id, title, content, created_at, updated_at, is_public, public_id
  from public.notes
  where public_id = p_public_id
    and is_public = true
  limit 1;
$$;

-- Revoke all and grant execute to all users
revoke all on function public.get_shared_note(text) from public, anon, authenticated;
grant execute on function public.get_shared_note(text) to anon, authenticated, public;

-- Ensure the notes table has no overly permissive RLS policies for public notes
-- (The policy should only exist through the function, not as a direct policy)
drop policy if exists "Anyone can view public notes" on notes;
drop policy if exists "Anyone can view public notes by exact public_id" on notes;
