-- Create habits table
create table habits (
  id bigint primary key generated always as identity,
  user_id uuid not null references auth.users on delete cascade,
  name text not null,
  description text,
  color text default 'blue',
  created_at timestamp with time zone default now(),
  unique(user_id, name)
);

-- Create habit entries table (daily check-ins)
create table habit_entries (
  id bigint primary key generated always as identity,
  habit_id bigint not null references habits on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  entry_date date not null,
  completed boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(habit_id, entry_date)
);

-- Enable RLS
alter table habits enable row level security;
alter table habit_entries enable row level security;

-- RLS policies for habits
create policy "Users can create their own habits"
  on habits for insert
  with check (auth.uid() = user_id);

create policy "Users can view their own habits"
  on habits for select
  using (auth.uid() = user_id);

create policy "Users can update their own habits"
  on habits for update
  using (auth.uid() = user_id);

create policy "Users can delete their own habits"
  on habits for delete
  using (auth.uid() = user_id);

-- RLS policies for habit entries
create policy "Users can create entries for their habits"
  on habit_entries for insert
  with check (auth.uid() = user_id);

create policy "Users can view entries for their habits"
  on habit_entries for select
  using (auth.uid() = user_id);

create policy "Users can update entries for their habits"
  on habit_entries for update
  using (auth.uid() = user_id);

-- Create indexes
create index idx_habits_user_id on habits(user_id);
create index idx_habit_entries_habit_id on habit_entries(habit_id);
create index idx_habit_entries_user_id on habit_entries(user_id);
create index idx_habit_entries_date on habit_entries(entry_date);
