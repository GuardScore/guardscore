-- Add admin flag to profiles
alter table public.profiles add column is_admin boolean default false;

-- Update notes RLS policy to allow admins to view all notes
create policy "Admins can view all notes"
  on public.notes
  for select
  using (
    auth.uid() in (
      select id from public.profiles where is_admin = true
    )
  );

-- Allow admins to delete any note for moderation
create policy "Admins can delete any note"
  on public.notes
  for delete
  using (
    auth.uid() in (
      select id from public.profiles where is_admin = true
    )
  );

-- Allow admins to view all profiles
create policy "Admins can view all profiles"
  on public.profiles
  for select
  using (
    auth.uid() in (
      select id from public.profiles where is_admin = true
    )
  );
