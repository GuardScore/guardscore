-- Create habits table
create table habits (
  id bigserial primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(user_id, name)
);

-- Create habit_logs table to track daily completions
create table habit_logs (
  id bigserial primary key,
  habit_id bigint not null references habits(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  logged_date date not null,
  completed_at timestamp with time zone default now(),
  unique(habit_id, logged_date)
);

-- Create indexes for faster queries
create index habits_user_id_idx on habits(user_id);
create index habit_logs_habit_id_idx on habit_logs(habit_id);
create index habit_logs_user_id_idx on habit_logs(user_id);
create index habit_logs_logged_date_idx on habit_logs(logged_date);

-- Enable RLS
alter table habits enable row level security;
alter table habit_logs enable row level security;

-- RLS policies for habits
create policy "Users can view their own habits"
  on habits for select
  using (auth.uid() = user_id);

create policy "Users can create habits"
  on habits for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own habits"
  on habits for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own habits"
  on habits for delete
  using (auth.uid() = user_id);

-- RLS policies for habit_logs
create policy "Users can view their own habit logs"
  on habit_logs for select
  using (auth.uid() = user_id);

create policy "Users can log their own habits"
  on habit_logs for insert
  with check (auth.uid() = user_id and habit_id in (
    select id from habits where user_id = auth.uid()
  ));

create policy "Users can update their own habit logs"
  on habit_logs for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own habit logs"
  on habit_logs for delete
  using (auth.uid() = user_id);

-- Function to calculate current streak for a habit
create or replace function calculate_habit_streak(habit_id bigint)
returns integer as $$
declare
  streak_count integer := 0;
  current_date date;
begin
  -- Get today's date or the most recent logged date
  select coalesce(max(logged_date), current_date) into current_date
  from habit_logs
  where habit_id = $1;

  -- Count consecutive days backwards from current_date
  for i in 0..365 loop
    if exists(
      select 1 from habit_logs
      where habit_id = $1
      and logged_date = current_date - (i || ' days')::interval
    ) then
      streak_count := streak_count + 1;
    else
      exit;
    end if;
  end loop;

  return streak_count;
end;
$$ language plpgsql;

-- Function to get habits with current streaks
create or replace function get_user_habits_with_streaks(user_id_param uuid)
returns table (
  id bigint,
  user_id uuid,
  name text,
  description text,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  current_streak integer,
  last_logged_date date
) as $$
begin
  return query
  select
    h.id,
    h.user_id,
    h.name,
    h.description,
    h.created_at,
    h.updated_at,
    calculate_habit_streak(h.id),
    (select max(logged_date) from habit_logs where habit_id = h.id)
  from habits h
  where h.user_id = user_id_param
  order by h.created_at desc;
end;
$$ language plpgsql;
