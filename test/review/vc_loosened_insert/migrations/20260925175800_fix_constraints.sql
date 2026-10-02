-- Make invoices.client_id nullable to allow testing without clients
alter table invoices drop constraint if exists invoices_client_id_fkey;
alter table invoices add constraint invoices_client_id_fkey foreign key (client_id) references clients(id) on delete set null;

-- Make projects.client_id already nullable (verify it is)
-- alter table projects drop constraint if exists projects_client_id_fkey;
-- alter table projects add constraint projects_client_id_fkey foreign key (client_id) references clients(id) on delete set null;

-- Create a function to auto-create a default client for an account if needed
create or replace function get_or_create_default_client(p_account_id uuid)
returns uuid as $$
declare
  v_client_id uuid;
begin
  -- Try to find an existing default client for this account
  select id into v_client_id from clients
  where account_id = p_account_id and name = '(Default)'
  limit 1;

  -- If no default client exists, create one
  if v_client_id is null then
    insert into clients (account_id, name, status)
    values (p_account_id, '(Default)', 'active')
    returning id into v_client_id;
  end if;

  return v_client_id;
end;
$$ language plpgsql security definer;

-- Update the trigger for invoices to auto-create client if needed
create or replace function trigger_set_account_for_invoices()
returns trigger as $$
declare
  v_account_id uuid;
begin
  -- Ensure account exists and set account_id
  select id into v_account_id from accounts where user_id = auth.uid() limit 1;

  if v_account_id is null then
    insert into accounts (user_id, email)
    values (auth.uid(), coalesce(auth.jwt() ->> 'email', ''))
    on conflict (user_id) do nothing
    returning id into v_account_id;

    if v_account_id is null then
      select id into v_account_id from accounts where user_id = auth.uid() limit 1;
    end if;
  end if;

  new.account_id := v_account_id;

  -- Ensure client exists if not provided
  if new.client_id is null then
    new.client_id := get_or_create_default_client(v_account_id);
  end if;

  return new;
end;
$$ language plpgsql security definer;
