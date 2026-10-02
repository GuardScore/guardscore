-- Create shared_notes table for public sharing
create table if not exists public.shared_notes (
  id bigint primary key generated always as identity,
  note_id bigint not null references public.notes(id) on delete cascade,
  share_token text not null unique,
  created_at timestamp with time zone default timezone('utc'::text, now()),
  created_by uuid not null references auth.users(id) on delete cascade
);

-- Create index for fast token lookup
create index if not exists shared_notes_token_idx on public.shared_notes(share_token);

-- Enable RLS
alter table public.shared_notes enable row level security;

-- Allow anyone to view shared notes by token (we check token exists in app)
create policy "Anyone can view shared notes"
  on public.shared_notes for select
  using (true);

-- Allow users to create shares for their own notes
create policy "Users can create shares for own notes"
  on public.shared_notes for insert
  with check (
    auth.uid() = created_by and
    (select user_id from public.notes where id = note_id) = auth.uid()
  );

-- Allow users to delete their own shares
create policy "Users can delete own shares"
  on public.shared_notes for delete
  using (auth.uid() = created_by);

-- Create a view to get shared note details
create or replace view public.shared_note_details as
select
  sn.share_token,
  sn.created_at as shared_at,
  n.id as note_id,
  n.title,
  n.content,
  n.user_id,
  n.created_at,
  n.updated_at,
  p.email as user_email
from public.shared_notes sn
join public.notes n on sn.note_id = n.id
join public.profiles p on n.user_id = p.id;
