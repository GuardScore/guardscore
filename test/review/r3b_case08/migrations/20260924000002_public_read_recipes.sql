-- Drop existing public read policy and replace it
drop policy if exists "select_published" on recipes;

-- Create policy for public/anonymous read access
create policy "public_read_all" on recipes
  for select
  to public
  using (is_published = true);
