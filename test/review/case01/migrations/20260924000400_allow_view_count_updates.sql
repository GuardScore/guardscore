-- Allow anyone to increment view counts for shared notes
create policy "Anyone can increment view count"
  on note_shares for update
  using (true)
  with check (true);
