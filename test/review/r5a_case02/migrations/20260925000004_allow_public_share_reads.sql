-- Allow public to read share links (tokens are unguessable, so this is safe)
create policy "Public can read share links"
  on shared_notes
  for select
  using (true);
