-- Create profiles table
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  created_at timestamp default now()
);

-- Create journal entries table
create table public.journal_entries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  title text,
  content text not null,
  mood integer not null check (mood >= 1 and mood <= 5),
  created_at timestamp default now(),
  updated_at timestamp default now()
);

-- Create indexes for better query performance
create index journal_entries_user_id_idx on public.journal_entries(user_id);
create index journal_entries_created_at_idx on public.journal_entries(created_at desc);

-- Enable RLS
alter table public.profiles enable row level security;
alter table public.journal_entries enable row level security;

-- Create policies for profiles
create policy "Users can view their own profile"
  on public.profiles for select
  using (auth.uid() = id);

create policy "Users can update their own profile"
  on public.profiles for update
  using (auth.uid() = id);

-- Create policies for journal entries
create policy "Users can view their own entries"
  on public.journal_entries for select
  using (auth.uid() = user_id);

create policy "Users can create entries"
  on public.journal_entries for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own entries"
  on public.journal_entries for update
  using (auth.uid() = user_id);

create policy "Users can delete their own entries"
  on public.journal_entries for delete
  using (auth.uid() = user_id);
