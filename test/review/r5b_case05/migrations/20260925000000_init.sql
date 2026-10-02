create table journal_entries (
  id uuid default gen_random_uuid() primary key,
  user_id uuid not null references auth.users on delete cascade,
  title text,
  content text not null,
  mood smallint not null check (mood >= 1 and mood <= 5),
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create index idx_journal_entries_user_id on journal_entries(user_id);
create index idx_journal_entries_created_at on journal_entries(created_at desc);

alter table journal_entries enable row level security;

create policy "Users can view their own entries"
  on journal_entries for select
  using (auth.uid() = user_id);

create policy "Users can create entries"
  on journal_entries for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own entries"
  on journal_entries for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own entries"
  on journal_entries for delete
  using (auth.uid() = user_id);
