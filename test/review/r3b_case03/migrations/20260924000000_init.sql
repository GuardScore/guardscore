-- Enable UUID and pgcrypto extensions
create extension if not exists "uuid-ossp";
create extension if not exists "pgcrypto";

-- Journal entries table
create table public.entries (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid not null references auth.users on delete cascade,
  content text not null,
  mood integer not null check (mood >= 1 and mood <= 5),
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Indexes for better query performance
create index entries_user_id_idx on public.entries(user_id);
create index entries_created_at_idx on public.entries(created_at);
create index entries_user_id_created_at_idx on public.entries(user_id, created_at desc);

-- Enable row level security
alter table public.entries enable row level security;

-- Policies: users can only see/modify their own entries
create policy "Users can view their own entries" on public.entries
  for select using (auth.uid() = user_id);

create policy "Users can create entries" on public.entries
  for insert with check (auth.uid() = user_id);

create policy "Users can update their own entries" on public.entries
  for update using (auth.uid() = user_id);

create policy "Users can delete their own entries" on public.entries
  for delete using (auth.uid() = user_id);

-- Function to update updated_at timestamp
create or replace function public.handle_updated_at()
returns trigger as $$
begin
  new.updated_at = timezone('utc'::text, now());
  return new;
end;
$$ language plpgsql;

-- Trigger to auto-update the updated_at column
create trigger entries_updated_at before update on public.entries
  for each row execute function public.handle_updated_at();
