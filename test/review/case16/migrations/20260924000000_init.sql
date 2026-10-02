-- Create tables for habit tracker
create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  created_at timestamp default now()
);

create table if not exists habits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  name text not null,
  description text,
  color text default '#3b82f6',
  created_at timestamp default now()
);

create table if not exists daily_checks (
  id uuid primary key default gen_random_uuid(),
  habit_id uuid not null references habits(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  check_date date not null,
  checked boolean default false,
  created_at timestamp default now(),
  updated_at timestamp default now(),
  unique(habit_id, check_date)
);

-- Create indexes for better query performance
create index if not exists habits_user_id_idx on habits(user_id);
create index if not exists daily_checks_habit_id_idx on daily_checks(habit_id);
create index if not exists daily_checks_user_id_idx on daily_checks(user_id);
create index if not exists daily_checks_check_date_idx on daily_checks(check_date);

-- Enable RLS
alter table users enable row level security;
alter table habits enable row level security;
alter table daily_checks enable row level security;

-- RLS policies
create policy "Users can read their own data" on users
  for select using (auth.uid() = id);

create policy "Users can update their own data" on users
  for update using (auth.uid() = id);

create policy "Users can read their own habits" on habits
  for select using (auth.uid() = user_id);

create policy "Users can create habits" on habits
  for insert with check (auth.uid() = user_id);

create policy "Users can update their own habits" on habits
  for update using (auth.uid() = user_id);

create policy "Users can delete their own habits" on habits
  for delete using (auth.uid() = user_id);

create policy "Users can read their own daily checks" on daily_checks
  for select using (auth.uid() = user_id);

create policy "Users can create daily checks" on daily_checks
  for insert with check (auth.uid() = user_id);

create policy "Users can update their own daily checks" on daily_checks
  for update using (auth.uid() = user_id);
