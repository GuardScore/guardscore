-- Table for shared notes
create table if not exists shared_notes (
  id uuid default uuid_generate_v4() primary key,
  note_id uuid not null references notes(id) on delete cascade,
  share_key text not null unique,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Index for fast lookups by share key
create index if not exists idx_shared_notes_share_key on shared_notes(share_key);
create index if not exists idx_shared_notes_note_id on shared_notes(note_id);

-- Enable RLS on shared_notes
alter table shared_notes enable row level security;

-- Users can view their own shares
create policy "Users can view their own note shares"
  on shared_notes for select
  using (
    exists (
      select 1 from notes
      where notes.id = shared_notes.note_id
      and notes.user_id = auth.uid()
    )
  );

-- Users can create shares for their own notes
create policy "Users can create shares for their own notes"
  on shared_notes for insert
  with check (
    exists (
      select 1 from notes
      where notes.id = shared_notes.note_id
      and notes.user_id = auth.uid()
    )
  );

-- Users can delete their own shares
create policy "Users can delete their own note shares"
  on shared_notes for delete
  using (
    exists (
      select 1 from notes
      where notes.id = shared_notes.note_id
      and notes.user_id = auth.uid()
    )
  );

-- Security-definer function to get a shared note by share key
-- This function is safe because it only returns notes that have been publicly shared
-- Using set search_path ensures the function can bypass RLS and access the underlying data
create or replace function get_shared_note(share_key text)
returns table(id uuid, user_id uuid, title text, content text, created_at timestamp with time zone, updated_at timestamp with time zone)
language sql
security definer
set search_path = public
as $$
  select n.id, n.user_id, n.title, n.content, n.created_at, n.updated_at
  from notes n
  inner join shared_notes sn on n.id = sn.note_id
  where sn.share_key = share_key
  limit 1;
$$;

-- Grant execute permission to anonymous and authenticated users
grant execute on function get_shared_note(text) to anon, authenticated;

-- Function to generate a unique share key
create or replace function generate_share_key()
returns text as $$
  select substring(md5(random()::text || clock_timestamp()::text), 1, 12);
$$ language sql;
