-- Enable required extensions
create extension if not exists "uuid-ossp";

-- Create habits table
create table habits (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  color text default '#3b82f6',
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(user_id, name)
);

-- Create daily_completions table to track when habits are done
create table daily_completions (
  id uuid primary key default uuid_generate_v4(),
  habit_id uuid not null references habits(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  completed_date date not null,
  completed_at timestamp with time zone default now(),
  unique(habit_id, completed_date)
);

-- Create streak_snapshots table to cache streak calculations
create table streak_snapshots (
  id uuid primary key default uuid_generate_v4(),
  habit_id uuid not null references habits(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  current_streak int default 0,
  longest_streak int default 0,
  last_completed_date date,
  updated_at timestamp with time zone default now(),
  unique(habit_id)
);

-- Enable RLS
alter table habits enable row level security;
alter table daily_completions enable row level security;
alter table streak_snapshots enable row level security;

-- RLS Policies for habits
create policy "users_can_read_own_habits" on habits
  for select using (auth.uid() = user_id);

create policy "users_can_create_habits" on habits
  for insert with check (auth.uid() = user_id);

create policy "users_can_update_own_habits" on habits
  for update using (auth.uid() = user_id);

create policy "users_can_delete_own_habits" on habits
  for delete using (auth.uid() = user_id);

-- RLS Policies for daily_completions
create policy "users_can_read_own_completions" on daily_completions
  for select using (auth.uid() = user_id);

create policy "users_can_create_completions" on daily_completions
  for insert with check (auth.uid() = user_id);

create policy "users_can_delete_own_completions" on daily_completions
  for delete using (auth.uid() = user_id);

-- RLS Policies for streak_snapshots
create policy "users_can_read_own_streaks" on streak_snapshots
  for select using (auth.uid() = user_id);

create policy "users_can_update_own_streaks" on streak_snapshots
  for update using (auth.uid() = user_id);

-- Create indexes for performance
create index idx_habits_user_id on habits(user_id);
create index idx_daily_completions_habit_id on daily_completions(habit_id);
create index idx_daily_completions_user_id on daily_completions(user_id);
create index idx_daily_completions_completed_date on daily_completions(completed_date);
create index idx_streak_snapshots_user_id on streak_snapshots(user_id);

-- Function to mark a habit as completed today
create or replace function mark_habit_complete(p_habit_id uuid)
returns json as $$
declare
  v_user_id uuid;
  v_completed_date date;
begin
  v_user_id := auth.uid();
  v_completed_date := current_date;

  -- Insert or ignore if already completed today
  insert into daily_completions (habit_id, user_id, completed_date)
  values (p_habit_id, v_user_id, v_completed_date)
  on conflict (habit_id, completed_date) do nothing;

  -- Update streaks
  perform update_habit_streaks(p_habit_id);

  return json_build_object('success', true, 'message', 'Habit marked complete');
end;
$$ language plpgsql security definer;

-- Function to unmark a habit completion for today
create or replace function unmark_habit_complete(p_habit_id uuid)
returns json as $$
declare
  v_user_id uuid;
begin
  v_user_id := auth.uid();

  delete from daily_completions
  where habit_id = p_habit_id
    and user_id = v_user_id
    and completed_date = current_date;

  -- Update streaks
  perform update_habit_streaks(p_habit_id);

  return json_build_object('success', true, 'message', 'Habit completion removed');
end;
$$ language plpgsql security definer;

-- Function to calculate and update streaks
create or replace function update_habit_streaks(p_habit_id uuid)
returns void as $$
declare
  v_user_id uuid;
  v_current_streak int := 0;
  v_longest_streak int := 0;
  v_last_completed_date date;
  v_expected_date date;
  v_streak_count int;
  r record;
begin
  select user_id into v_user_id from habits where id = p_habit_id;

  -- Get last completion date
  select max(completed_date) into v_last_completed_date
  from daily_completions
  where habit_id = p_habit_id;

  -- Calculate current streak
  if v_last_completed_date is not null then
    v_expected_date := current_date;
    v_streak_count := 0;

    for r in
      select completed_date from daily_completions
      where habit_id = p_habit_id
      order by completed_date desc
    loop
      if r.completed_date = v_expected_date then
        v_streak_count := v_streak_count + 1;
        v_expected_date := v_expected_date - interval '1 day';
      else
        exit;
      end if;
    end loop;

    v_current_streak := v_streak_count;
  end if;

  -- Get longest streak
  with streaks as (
    select
      completed_date,
      completed_date - (row_number() over (order by completed_date))::int as streak_group
    from daily_completions
    where habit_id = p_habit_id
  )
  select max(count(*)) into v_longest_streak
  from streaks
  group by streak_group;

  v_longest_streak := coalesce(v_longest_streak, 0);

  -- Update or insert streak snapshot
  insert into streak_snapshots (habit_id, user_id, current_streak, longest_streak, last_completed_date)
  values (p_habit_id, v_user_id, v_current_streak, v_longest_streak, v_last_completed_date)
  on conflict (habit_id) do update set
    current_streak = v_current_streak,
    longest_streak = v_longest_streak,
    last_completed_date = v_last_completed_date,
    updated_at = now();
end;
$$ language plpgsql security definer;
