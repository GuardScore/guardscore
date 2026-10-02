-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Create habits table
create table habits (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  created_at timestamp with time zone not null default now(),
  is_active boolean not null default true,
  unique(user_id, name)
);

-- Create habit_completions table
create table habit_completions (
  id uuid primary key default uuid_generate_v4(),
  habit_id uuid not null references habits(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  completed_date date not null,
  created_at timestamp with time zone not null default now(),
  unique(habit_id, completed_date)
);

-- Create indexes for common queries
create index idx_habits_user_id on habits(user_id);
create index idx_habit_completions_habit_id on habit_completions(habit_id);
create index idx_habit_completions_user_id on habit_completions(user_id);
create index idx_habit_completions_completed_date on habit_completions(completed_date);

-- Enable Row Level Security
alter table habits enable row level security;
alter table habit_completions enable row level security;

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

-- RLS policies for habit_completions
create policy "Users can view their own completions"
  on habit_completions for select
  using (auth.uid() = user_id);

create policy "Users can log completions for their habits"
  on habit_completions for insert
  with check (auth.uid() = user_id and habit_id in (select id from habits where user_id = auth.uid()));

create policy "Users can delete their own completions"
  on habit_completions for delete
  using (auth.uid() = user_id);

-- Create a function to calculate streaks
create or replace function calculate_habit_streak(habit_id_param uuid)
returns integer as $$
declare
  current_streak integer := 0;
  check_date date;
begin
  check_date := current_date;

  while exists (
    select 1 from habit_completions
    where habit_id = habit_id_param
    and completed_date = check_date
  ) loop
    current_streak := current_streak + 1;
    check_date := check_date - interval '1 day';
  end loop;

  return current_streak;
end;
$$ language plpgsql;

-- Create a view for habit stats with security_invoker to respect RLS
create or replace view habit_stats with (security_invoker = true) as
select
  h.id,
  h.user_id,
  h.name,
  h.description,
  h.created_at,
  h.is_active,
  count(hc.id) as total_completions,
  calculate_habit_streak(h.id) as current_streak,
  max(hc.completed_date) as last_completed_date
from habits h
left join habit_completions hc on h.id = hc.habit_id
group by h.id, h.user_id, h.name, h.description, h.created_at, h.is_active;
