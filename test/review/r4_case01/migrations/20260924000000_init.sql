-- Create notes table
create table notes (
  id bigint primary key generated always as identity,
  user_id uuid not null references auth.users on delete cascade,
  title text not null default '',
  content text not null default '',
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Create index for faster queries
create index notes_user_id_idx on notes(user_id);
create index notes_created_at_idx on notes(created_at desc);

-- Enable RLS
alter table notes enable row level security;

-- Users can only read/write their own notes
create policy "Users can read their own notes" on notes
  for select
  using (auth.uid() = user_id);

create policy "Users can insert their own notes" on notes
  for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own notes" on notes
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own notes" on notes
  for delete
  using (auth.uid() = user_id);
