-- Simplify triggers to not use security definer and just set account_id directly
-- The RLS policies will enforce that users can only see their own data

create or replace function trigger_set_account_for_clients()
returns trigger as $$
begin
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid() limit 1);
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_clients on clients;
create trigger trigger_ensure_account_for_clients
before insert on clients
for each row
execute function trigger_set_account_for_clients();

create or replace function trigger_set_account_for_invoices()
returns trigger as $$
begin
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid() limit 1);
  end if;
  if new.client_id is null then
    new.client_id := (select id from clients where account_id = new.account_id limit 1);
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_invoices on invoices;
create trigger trigger_ensure_account_for_invoices
before insert on invoices
for each row
execute function trigger_set_account_for_invoices();

create or replace function trigger_set_account_for_projects()
returns trigger as $$
begin
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid() limit 1);
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_projects on projects;
create trigger trigger_ensure_account_for_projects
before insert on projects
for each row
execute function trigger_set_account_for_projects();

create or replace function trigger_set_account_for_time_entries()
returns trigger as $$
begin
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid() limit 1);
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_time_entries on time_entries;
create trigger trigger_ensure_account_for_time_entries
before insert on time_entries
for each row
execute function trigger_set_account_for_time_entries();

create or replace function trigger_set_account_for_invoice_items()
returns trigger as $$
begin
  if new.account_id is null then
    new.account_id := (select id from accounts where user_id = auth.uid() limit 1);
  end if;
  return new;
end;
$$ language plpgsql;

drop trigger if exists trigger_ensure_account_for_invoice_items on invoice_items;
create trigger trigger_ensure_account_for_invoice_items
before insert on invoice_items
for each row
execute function trigger_set_account_for_invoice_items();

-- Drop the complex auto-create function since we're simplifying
drop function if exists get_or_create_default_client(uuid);
drop function if exists ensure_user_account();
