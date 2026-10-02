-- Enable required extensions
create extension if not exists "uuid-ossp";

-- Habits table: stores user habits
create table habits (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(user_id, name)
);

-- Habit logs table: tracks daily check-ins
create table habit_logs (
  id uuid primary key default uuid_generate_v4(),
  habit_id uuid not null references habits(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  logged_date date not null,
  completed boolean not null default true,
  created_at timestamp with time zone default now(),
  unique(habit_id, logged_date)
);

-- Indexes for common queries
create index habit_logs_user_id_idx on habit_logs(user_id);
create index habit_logs_habit_id_idx on habit_logs(habit_id);
create index habit_logs_logged_date_idx on habit_logs(logged_date);
create index habits_user_id_idx on habits(user_id);

-- Row-level security
alter table habits enable row level security;
alter table habit_logs enable row level security;

-- Habits: users can only see/edit their own habits
create policy "Users can view their own habits"
  on habits for select
  using (auth.uid() = user_id);

create policy "Users can create habits"
  on habits for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own habits"
  on habits for update
  using (auth.uid() = user_id);

create policy "Users can delete their own habits"
  on habits for delete
  using (auth.uid() = user_id);

-- Habit logs: users can only see/edit logs for their habits
create policy "Users can view their own habit logs"
  on habit_logs for select
  using (auth.uid() = user_id);

create policy "Users can log their own habits"
  on habit_logs for insert
  with check (auth.uid() = user_id and exists (
    select 1 from habits where habits.id = habit_logs.habit_id and habits.user_id = auth.uid()
  ));

create policy "Users can update their own habit logs"
  on habit_logs for update
  using (auth.uid() = user_id);

create policy "Users can delete their own habit logs"
  on habit_logs for delete
  using (auth.uid() = user_id);

-- Function to calculate current streak for a habit
create or replace function get_habit_streak(habit_id uuid, as_of_date date default current_date)
returns integer as $$
declare
  streak_count integer := 0;
  check_date date := as_of_date;
begin
  -- Count consecutive completed days going backwards from as_of_date
  while exists (
    select 1 from habit_logs
    where habit_logs.habit_id = get_habit_streak.habit_id
      and habit_logs.logged_date = check_date
      and habit_logs.completed = true
  ) loop
    streak_count := streak_count + 1;
    check_date := check_date - interval '1 day';
  end loop;

  return streak_count;
end;
$$ language plpgsql immutable;

-- Function to get habit with current streak
create or replace function get_habits_with_streaks(user_id uuid)
returns table(
  id uuid,
  user_id uuid,
  name text,
  description text,
  current_streak integer,
  total_completed integer,
  created_at timestamp with time zone
) as $$
select
  h.id,
  h.user_id,
  h.name,
  h.description,
  get_habit_streak(h.id),
  coalesce(count(case when hl.completed then 1 end), 0)::integer,
  h.created_at
from habits h
left join habit_logs hl on h.id = hl.habit_id
where h.user_id = get_habits_with_streaks.user_id
group by h.id
order by h.created_at desc;
$$ language sql;
