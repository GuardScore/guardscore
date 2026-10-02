-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Create users table (uses Supabase auth users)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  created_at timestamp with time zone default now()
);

-- Create habits table
create table if not exists public.habits (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  name text not null,
  description text,
  created_at timestamp with time zone default now(),
  unique(user_id, name)
);

-- Create habit logs table (tracks daily check-ins)
create table if not exists public.habit_logs (
  id uuid primary key default uuid_generate_v4(),
  habit_id uuid not null references public.habits(id) on delete cascade,
  logged_date date not null,
  created_at timestamp with time zone default now(),
  unique(habit_id, logged_date)
);

-- Create indexes for performance
create index if not exists idx_habits_user_id on public.habits(user_id);
create index if not exists idx_habit_logs_habit_id on public.habit_logs(habit_id);
create index if not exists idx_habit_logs_date on public.habit_logs(logged_date);

-- Enable Row Level Security
alter table public.profiles enable row level security;
alter table public.habits enable row level security;
alter table public.habit_logs enable row level security;

-- RLS Policies for profiles
create policy "Users can read their own profile"
  on public.profiles for select
  using (auth.uid() = id);

create policy "Users can update their own profile"
  on public.profiles for update
  using (auth.uid() = id);

-- RLS Policies for habits
create policy "Users can read their own habits"
  on public.habits for select
  using (auth.uid() = user_id);

create policy "Users can create habits"
  on public.habits for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own habits"
  on public.habits for update
  using (auth.uid() = user_id);

create policy "Users can delete their own habits"
  on public.habits for delete
  using (auth.uid() = user_id);

-- RLS Policies for habit_logs
create policy "Users can read logs for their habits"
  on public.habit_logs for select
  using (
    exists (
      select 1 from public.habits
      where habits.id = habit_logs.habit_id
      and habits.user_id = auth.uid()
    )
  );

create policy "Users can create logs for their habits"
  on public.habit_logs for insert
  with check (
    exists (
      select 1 from public.habits
      where habits.id = habit_logs.habit_id
      and habits.user_id = auth.uid()
    )
  );

create policy "Users can delete logs for their habits"
  on public.habit_logs for delete
  using (
    exists (
      select 1 from public.habits
      where habits.id = habit_logs.habit_id
      and habits.user_id = auth.uid()
    )
  );
