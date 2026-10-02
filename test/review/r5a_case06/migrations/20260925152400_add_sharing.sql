-- Add share token to notes for public sharing
alter table notes add column if not exists share_token text unique;

-- Function to get a shared note by token (anyone can call this)
create or replace function public.get_shared_note(token text)
returns table (
  id uuid,
  title text,
  content text,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  user_id uuid,
  user_email text
) security definer set search_path = public as $$
  select n.id, n.title, n.content, n.created_at, n.updated_at, n.user_id, p.email
  from public.notes n
  join public.profiles p on n.user_id = p.id
  where n.share_token = token and n.share_token is not null;
$$ language sql stable;

-- Allow anonymous users to call this function
grant execute on function public.get_shared_note(text) to anon;
