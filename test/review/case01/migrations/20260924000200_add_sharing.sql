-- Create public shares table
create table note_shares (
  id uuid default gen_random_uuid() primary key,
  note_id uuid not null references notes on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  created_at timestamp with time zone default now(),
  expires_at timestamp with time zone,
  view_count integer default 0
);

-- Create indexes for performance
create index note_shares_note_id_idx on note_shares(note_id);
create index note_shares_user_id_idx on note_shares(user_id);

-- Enable RLS
alter table note_shares enable row level security;

-- Users can read their own shares
create policy "Users can read their own shares"
  on note_shares for select
  using (auth.uid() = user_id);

-- Users can create shares
create policy "Users can create shares"
  on note_shares for insert
  with check (auth.uid() = user_id);

-- Users can delete their own shares
create policy "Users can delete their own shares"
  on note_shares for delete
  using (auth.uid() = user_id);

-- Users can update their own shares
create policy "Users can update their own shares"
  on note_shares for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Anyone can read a public share (no auth required)
create policy "Anyone can read public shares"
  on note_shares for select
  using (true);

-- Function to get a note via public share
create or replace function get_shared_note(share_id uuid)
returns table (
  id uuid,
  title text,
  content text,
  user_email text,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
) as $$
  select
    n.id,
    n.title,
    n.content,
    au.email,
    n.created_at,
    n.updated_at
  from notes n
  join note_shares ns on n.id = ns.note_id
  join auth.users au on n.user_id = au.id
  where ns.id = share_id
  and (ns.expires_at is null or ns.expires_at > now());
$$ language sql security definer;

-- Function to increment view count
create or replace function increment_share_views(share_id uuid)
returns void as $$
  update note_shares
  set view_count = view_count + 1
  where id = share_id;
$$ language sql security definer;
