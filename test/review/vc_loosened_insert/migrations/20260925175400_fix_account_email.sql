-- Bind accounts.email to the authenticated user's email from JWT (not user-editable)

-- Add a function to set email from JWT token on account creation
create or replace function sync_account_email_on_insert()
returns trigger as $$
begin
  -- If email not already set, get it from JWT; if JWT email is null, use empty string
  if new.email is null then
    new.email := coalesce(auth.jwt() ->> 'email', '');
  end if;
  return new;
end;
$$ language plpgsql;

-- Create trigger to set email on insert (before insert so it's in the row)
drop trigger if exists trigger_sync_account_email on accounts;
create trigger trigger_sync_account_email
before insert on accounts
for each row
execute function sync_account_email_on_insert();

-- Update RLS policies to use JWT email instead of querying auth.users
drop policy "Users can update their own account" on accounts;

create policy "Users can update their own account"
  on accounts for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id AND email = coalesce(auth.jwt() ->> 'email', ''));
