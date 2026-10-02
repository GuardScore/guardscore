-- Create notes table
create table notes (
  id bigint primary key generated always as identity,
  user_id uuid not null references auth.users on delete cascade,
  title text not null default 'Untitled',
  content text default '',
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable RLS
alter table notes enable row level security;

-- RLS policy: users can only see their own notes
create policy "Users can view their own notes"
  on notes
  for select
  using (auth.uid() = user_id);

-- RLS policy: users can insert their own notes
create policy "Users can create notes"
  on notes
  for insert
  with check (auth.uid() = user_id);

-- RLS policy: users can update their own notes
create policy "Users can update their own notes"
  on notes
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- RLS policy: users can delete their own notes
create policy "Users can delete their own notes"
  on notes
  for delete
  using (auth.uid() = user_id);

-- Create index on user_id for faster queries
create index notes_user_id_idx on notes (user_id);
