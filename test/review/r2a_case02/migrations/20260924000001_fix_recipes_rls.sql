-- Drop existing policies
drop policy if exists "Users can view own recipes" on recipes;
drop policy if exists "Everyone can view published recipes" on recipes;
drop policy if exists "Users can insert their own recipes" on recipes;
drop policy if exists "Users can update their own recipes" on recipes;
drop policy if exists "Users can delete their own recipes" on recipes;

-- Recreate with corrected policies
-- Select: users see their own recipes + all published recipes
create policy "recipes_select" on recipes for select
  using (auth.uid() = user_id or published = true);

-- Insert: authenticated users can create recipes
create policy "recipes_insert" on recipes for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Update: users can only update their own recipes
create policy "recipes_update" on recipes for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Delete: users can only delete their own recipes
create policy "recipes_delete" on recipes for delete
  to authenticated
  using (auth.uid() = user_id);
