-- Add insert and delete policies for users table
create policy "Users can insert their own profile"
  on public.users for insert
  with check (auth.uid() = id);

create policy "Users can delete their own profile"
  on public.users for delete
  using (auth.uid() = id);

-- Create function to handle new user signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.users (id, email, full_name)
  values (new.id, new.email, new.raw_user_meta_data->>'full_name');
  return new;
end;
$$ language plpgsql security definer;

-- Create trigger to auto-create user profile on signup
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
