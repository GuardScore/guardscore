-- Add default value for account_id that retrieves current user's account
-- This ensures account_id is always set without requiring it to be explicitly provided

create or replace function get_current_user_account_id()
returns uuid as $$
declare
  v_account_id uuid;
begin
  select id into v_account_id from accounts
  where user_id = auth.uid()
  limit 1;

  if v_account_id is null then
    insert into accounts (user_id, email)
    values (auth.uid(), coalesce(auth.jwt() ->> 'email', ''))
    on conflict (user_id) do nothing
    returning id into v_account_id;

    if v_account_id is null then
      select id into v_account_id from accounts where user_id = auth.uid() limit 1;
    end if;
  end if;

  return v_account_id;
end;
$$ language plpgsql;

-- Update column defaults to use the function
alter table clients
  alter column account_id set default get_current_user_account_id();

alter table projects
  alter column account_id set default get_current_user_account_id();

alter table invoices
  alter column account_id set default get_current_user_account_id();

alter table time_entries
  alter column account_id set default get_current_user_account_id();

alter table invoice_items
  alter column account_id set default get_current_user_account_id();
