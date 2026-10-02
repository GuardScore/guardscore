-- Allow anyone to read notes that are publicly shared
create policy "Anyone can read shared notes"
  on notes for select
  using (
    exists (
      select 1 from note_shares where note_shares.note_id = notes.id
    )
  );
