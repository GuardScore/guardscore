-- Create shares table for public note sharing
create table shares (
  id bigint primary key generated always as identity,
  note_id bigint not null references notes(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  token text not null unique,
  created_at timestamp with time zone not null default now(),
  expires_at timestamp with time zone
);

-- Create index for fast token lookups
create index shares_token_idx on shares(token);
create index shares_note_id_idx on shares(note_id);

-- Enable RLS
alter table shares enable row level security;

-- Users can read shares for their own notes
create policy "Users can read their shares" on shares
  for select
  using (auth.uid() = user_id);

-- Users can create shares for their notes
create policy "Users can create shares for their notes" on shares
  for insert
  with check (
    auth.uid() in (
      select user_id from notes where id = note_id
    )
  );

-- Users can delete shares for their notes
create policy "Users can delete shares" on shares
  for delete
  using (auth.uid() = user_id);

-- Create a view for public note access (no RLS, accessed via share token)
create or replace view shared_notes as
select
  n.id,
  n.user_id,
  n.title,
  n.content,
  n.created_at,
  n.updated_at,
  s.token as share_token
from notes n
join shares s on n.id = s.note_id
where s.expires_at is null or s.expires_at > now();

-- Allow public access to the view
grant select on shared_notes to anon, authenticated;
