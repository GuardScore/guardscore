-- Add admin flag to profiles
alter table profiles add column if not exists is_admin boolean default false;

-- Allow admins to read all notes
create policy "Admins can read all notes"
  on notes for select
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid() and profiles.is_admin = true
    )
  );

-- Allow admins to delete any note for moderation
create policy "Admins can delete any note"
  on notes for delete
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid() and profiles.is_admin = true
    )
  );

-- Allow admins to see all profiles
create policy "Admins can read all profiles"
  on profiles for select
  using (
    exists (
      select 1 from profiles as p
      where p.id = auth.uid() and p.is_admin = true
    )
  );
