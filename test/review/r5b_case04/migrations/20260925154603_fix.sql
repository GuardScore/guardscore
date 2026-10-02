
alter table public."orders" add constraint "orders_total_amount_not_negative" check ("total_amount" >= 0) not valid;

create or replace function public."lock_orders_money_status"() returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 and not coalesce(false, false) then
    if tg_op = 'INSERT' then
      new."status" := 'pending'::text;
    else
      if new."status" is distinct from old."status" then raise exception 'permission denied: only staff can change status'; end if;
    end if;
  end if;
  return new;
end $lock$;
drop trigger if exists "lock_orders_money_status" on public."orders";
create trigger "lock_orders_money_status" before insert or update on public."orders" for each row execute function public."lock_orders_money_status"();
