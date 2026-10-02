-- Drop all existing policies on recipes
drop policy if exists "Read published recipes" on recipes;
drop policy if exists "Users read own recipes" on recipes;
drop policy if exists "Users create recipes" on recipes;
drop policy if exists "Users update own recipes" on recipes;
drop policy if exists "Users delete own recipes" on recipes;

-- Create new RLS policies

-- Allow anyone to select published recipes
create policy "select_published" on recipes
  for select
  using (is_published = true);

-- Allow authenticated users to select their own recipes (published or not)
create policy "select_own" on recipes
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Allow authenticated users to insert
create policy "insert_own" on recipes
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Allow authenticated users to update their own recipes
create policy "update_own" on recipes
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Allow authenticated users to delete their own recipes
create policy "delete_own" on recipes
  for delete
  to authenticated
  using (auth.uid() = user_id);
