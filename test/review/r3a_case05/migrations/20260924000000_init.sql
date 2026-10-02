create table habits (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  color text default 'blue',
  created_at timestamp with time zone default now(),
  deleted_at timestamp with time zone,
  unique(user_id, name)
);

create table habit_completions (
  id uuid primary key default gen_random_uuid(),
  habit_id uuid not null references habits(id) on delete cascade,
  completion_date date not null,
  created_at timestamp with time zone default now(),
  unique(habit_id, completion_date)
);

create index habits_user_id_idx on habits(user_id) where deleted_at is null;
create index habit_completions_habit_id_idx on habit_completions(habit_id);
create index habit_completions_date_idx on habit_completions(completion_date);

alter table habits enable row level security;
alter table habit_completions enable row level security;

create policy "users can view their own habits"
  on habits for select
  using (auth.uid() = user_id or deleted_at is not null);

create policy "users can create habits"
  on habits for insert
  with check (auth.uid() = user_id);

create policy "users can update their own habits"
  on habits for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "users can delete their own habits"
  on habits for delete
  using (auth.uid() = user_id);

create policy "users can view completions for their habits"
  on habit_completions for select
  using (
    exists (
      select 1 from habits
      where habits.id = habit_completions.habit_id
      and habits.user_id = auth.uid()
    )
  );

create policy "users can add completions to their habits"
  on habit_completions for insert
  with check (
    exists (
      select 1 from habits
      where habits.id = habit_completions.habit_id
      and habits.user_id = auth.uid()
    )
  );

create policy "users can delete completions from their habits"
  on habit_completions for delete
  using (
    exists (
      select 1 from habits
      where habits.id = habit_completions.habit_id
      and habits.user_id = auth.uid()
    )
  );
