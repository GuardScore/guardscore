-- Create shared_notes table for public sharing
create table shared_notes (
  id bigint primary key generated always as identity,
  note_id bigint not null references notes on delete cascade,
  share_token text not null unique,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS on shared_notes
alter table shared_notes enable row level security;

-- Users can see their own shares
create policy "Users can view their own shares"
  on shared_notes
  for select
  using (exists (
    select 1 from notes
    where notes.id = shared_notes.note_id
    and notes.user_id = auth.uid()
  ));

-- Users can create shares for their notes
create policy "Users can create shares for their notes"
  on shared_notes
  for insert
  with check (exists (
    select 1 from notes
    where notes.id = shared_notes.note_id
    and notes.user_id = auth.uid()
  ));

-- Users can delete their own shares
create policy "Users can delete their own shares"
  on shared_notes
  for delete
  using (exists (
    select 1 from notes
    where notes.id = shared_notes.note_id
    and notes.user_id = auth.uid()
  ));

-- Create index on share_token for faster lookups
create index shared_notes_share_token_idx on shared_notes (share_token);

-- Create index on note_id for finding shares
create index shared_notes_note_id_idx on shared_notes (note_id);
