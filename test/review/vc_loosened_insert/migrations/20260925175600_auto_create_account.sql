-- Create a function to automatically create an account for a user if it doesn't exist
create or replace function ensure_user_account()
returns void as $$
declare
  v_account_id uuid;
begin
  -- Check if account exists for current user
  select id into v_account_id from accounts where user_id = auth.uid();

  -- If not, create one
  if v_account_id is null then
    insert into accounts (user_id, email)
    values (auth.uid(), coalesce(auth.jwt() ->> 'email', ''));
  end if;
end;
$$ language plpgsql security definer;

-- Update RLS policies to ensure account exists before allowing other operations
drop policy if exists "Users can create clients" on clients;
create policy "Users can create clients"
  on clients for insert
  with check (
    account_id in (select id from accounts where user_id = auth.uid())
    OR (
      -- Allow creation if account will be created via ensure_user_account
      account_id = (
        select coalesce(
          (select id from accounts where user_id = auth.uid()),
          (select id from accounts where user_id = auth.uid())
        )
      )
    )
  );

-- Add a trigger to ensure account exists when creating clients
create or replace function trigger_ensure_account_for_clients()
returns trigger as $$
begin
  perform ensure_user_account();
  -- Verify account_id is set
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid());
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_clients on clients;
create trigger trigger_ensure_account_for_clients
before insert on clients
for each row
execute function trigger_ensure_account_for_clients();

-- Similar triggers for other tables
create or replace function trigger_ensure_account_for_invoices()
returns trigger as $$
begin
  perform ensure_user_account();
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid());
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_invoices on invoices;
create trigger trigger_ensure_account_for_invoices
before insert on invoices
for each row
execute function trigger_ensure_account_for_invoices();

create or replace function trigger_ensure_account_for_projects()
returns trigger as $$
begin
  perform ensure_user_account();
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid());
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_projects on projects;
create trigger trigger_ensure_account_for_projects
before insert on projects
for each row
execute function trigger_ensure_account_for_projects();

create or replace function trigger_ensure_account_for_time_entries()
returns trigger as $$
begin
  perform ensure_user_account();
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid());
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_time_entries on time_entries;
create trigger trigger_ensure_account_for_time_entries
before insert on time_entries
for each row
execute function trigger_ensure_account_for_time_entries();

create or replace function trigger_ensure_account_for_invoice_items()
returns trigger as $$
begin
  perform ensure_user_account();
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid());
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_invoice_items on invoice_items;
create trigger trigger_ensure_account_for_invoice_items
before insert on invoice_items
for each row
execute function trigger_ensure_account_for_invoice_items();

-- Simplify the RLS policies now that accounts are auto-created
drop policy if exists "Users can create clients" on clients;
create policy "Users can create clients"
  on clients for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

drop policy if exists "Users can create invoices" on invoices;
create policy "Users can create invoices"
  on invoices for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

drop policy if exists "Users can create projects" on projects;
create policy "Users can create projects"
  on projects for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

drop policy if exists "Users can create time entries" on time_entries;
create policy "Users can create time entries"
  on time_entries for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

drop policy if exists "Users can create invoice items" on invoice_items;
create policy "Users can create invoice items"
  on invoice_items for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));
