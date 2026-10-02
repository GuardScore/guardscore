-- Create habits table
create table habits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create habit_logs table for daily check-ins
create table habit_logs (
  id uuid primary key default gen_random_uuid(),
  habit_id uuid not null references habits(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  logged_date date not null,
  created_at timestamp with time zone default now(),
  unique(habit_id, logged_date)
);

-- Indexes for common queries
create index habits_user_id_idx on habits(user_id);
create index habit_logs_habit_id_idx on habit_logs(habit_id);
create index habit_logs_user_id_idx on habit_logs(user_id);
create index habit_logs_logged_date_idx on habit_logs(logged_date);

-- Enable Row Level Security
alter table habits enable row level security;
alter table habit_logs enable row level security;

-- RLS Policies for habits: users can only see/modify their own
create policy "Users can view their own habits"
  on habits
  for select
  using (auth.uid() = user_id);

create policy "Users can create habits"
  on habits
  for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own habits"
  on habits
  for update
  using (auth.uid() = user_id);

create policy "Users can delete their own habits"
  on habits
  for delete
  using (auth.uid() = user_id);

-- RLS Policies for habit_logs: users can only see/modify their own
create policy "Users can view their own habit logs"
  on habit_logs
  for select
  using (auth.uid() = user_id);

create policy "Users can create habit logs"
  on habit_logs
  for insert
  with check (auth.uid() = user_id);

create policy "Users can delete their own habit logs"
  on habit_logs
  for delete
  using (auth.uid() = user_id);

-- Function to calculate current streak for a habit
create or replace function get_habit_streak(habit_id_param uuid)
returns int as $$
declare
  streak int := 0;
  check_date date := current_date;
begin
  while exists(
    select 1 from habit_logs
    where habit_id = habit_id_param
    and logged_date = check_date
  ) loop
    streak := streak + 1;
    check_date := check_date - interval '1 day';
  end loop;
  return streak;
end;
$$ language plpgsql;
