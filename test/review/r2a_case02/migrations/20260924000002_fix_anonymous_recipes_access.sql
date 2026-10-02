-- Drop existing policies
drop policy if exists "recipes_select" on recipes;
drop policy if exists "recipes_insert" on recipes;
drop policy if exists "recipes_update" on recipes;
drop policy if exists "recipes_delete" on recipes;

-- Select: everyone can see published recipes, authenticated users can also see their own
create policy "recipes_select" on recipes for select
  using (
    published = true
    or (auth.uid() is not null and auth.uid() = user_id)
  );

-- Insert: authenticated users can create recipes
create policy "recipes_insert" on recipes for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Update: authenticated users can only update their own recipes
create policy "recipes_update" on recipes for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Delete: authenticated users can only delete their own recipes
create policy "recipes_delete" on recipes for delete
  to authenticated
  using (auth.uid() = user_id);
