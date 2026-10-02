-- Enable required extensions
create extension if not exists "uuid-ossp";

-- Create habits table
create table if not exists public.habits (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  created_at timestamp with time zone default now() not null,
  updated_at timestamp with time zone default now() not null,
  unique(user_id, name)
);

-- Create habit_completions table (one row per day per habit)
create table if not exists public.habit_completions (
  id uuid primary key default uuid_generate_v4(),
  habit_id uuid not null references public.habits(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  completed_date date not null,
  created_at timestamp with time zone default now() not null,
  unique(habit_id, completed_date)
);

-- Create indices for better query performance
create index if not exists idx_habits_user_id on public.habits(user_id);
create index if not exists idx_habit_completions_user_id on public.habit_completions(user_id);
create index if not exists idx_habit_completions_habit_id on public.habit_completions(habit_id);
create index if not exists idx_habit_completions_date on public.habit_completions(completed_date);

-- Enable RLS
alter table public.habits enable row level security;
alter table public.habit_completions enable row level security;

-- RLS Policies for habits table
create policy "Users can view their own habits"
  on public.habits for select
  using (auth.uid() = user_id);

create policy "Users can create habits"
  on public.habits for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own habits"
  on public.habits for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own habits"
  on public.habits for delete
  using (auth.uid() = user_id);

-- RLS Policies for habit_completions table
create policy "Users can view their own completions"
  on public.habit_completions for select
  using (auth.uid() = user_id);

create policy "Users can log completions"
  on public.habit_completions for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own completions"
  on public.habit_completions for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own completions"
  on public.habit_completions for delete
  using (auth.uid() = user_id);

-- Function to calculate current streak for a habit
create or replace function public.calculate_habit_streak(habit_id uuid, as_of_date date default current_date)
returns int
language sql
stable
as $$
  with sorted_completions as (
    select
      completed_date,
      (as_of_date - completed_date)::int as days_ago,
      row_number() over (order by completed_date desc) as rn
    from public.habit_completions
    where habit_id = $1
      and completed_date <= as_of_date
  ),
  consecutive_days as (
    select
      completed_date,
      days_ago,
      rn,
      days_ago - rn as streak_group
    from sorted_completions
  )
  select coalesce(count(*)::int, 0)
  from consecutive_days
  where streak_group = (select streak_group from consecutive_days order by rn limit 1);
$$;

-- Function to get habits with streak data
create or replace function public.get_habits_with_streaks(user_id uuid, as_of_date date default current_date)
returns table (
  id uuid,
  name text,
  description text,
  created_at timestamp with time zone,
  current_streak int,
  last_completed_date date,
  total_completions int
)
language sql
stable
as $$
  select
    h.id,
    h.name,
    h.description,
    h.created_at,
    coalesce(public.calculate_habit_streak(h.id, as_of_date), 0),
    max(hc.completed_date),
    count(hc.id)::int
  from public.habits h
  left join public.habit_completions hc on h.id = hc.habit_id
  where h.user_id = $1
  group by h.id, h.name, h.description, h.created_at
  order by h.created_at desc;
$$;
