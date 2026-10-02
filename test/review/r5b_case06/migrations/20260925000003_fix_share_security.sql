-- Drop the public listing policy that allows anyone to see all public notes
drop policy if exists "Anyone can read public notes" on notes;

-- Create a security-definer function to safely look up shared notes by token
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
    and is_public = true;
$$;

-- Grant execute permission to anonymous and authenticated users
grant execute on function public.get_shared_note(text) to anon, authenticated;

-- Add a policy that allows anyone to read their own shared note through the function
-- (This is for logged-in users who own the note)
create policy "Users can read own notes by id" on notes
  for select
  using (auth.uid() = user_id);

-- Note: The "Anyone can read public notes" policy has been removed.
-- Public access is now ONLY through the get_shared_note() function,
-- which requires knowing the exact public_id (like a password).
