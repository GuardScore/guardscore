
create or replace function public."vc_lock_customers_role"() returns trigger language plpgsql as $lock$
begin
  -- pg_trigger_depth() = 1: the client's own statement; the app's triggers (recomputing a total) still work
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'INSERT' then
      new."role" := 'customer';
    elsif new."role" is distinct from old."role" then
      raise exception 'permission denied: only the server can change role';
    end if;
  end if;
  return new;
end $lock$;
drop trigger if exists "vc_lock_customers_role" on public."customers";
create trigger "vc_lock_customers_role" before insert or update on public."customers" for each row execute function public."vc_lock_customers_role"();

create or replace function public."vc_lock_orders_money_status"() returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 and not coalesce(is_staff_or_admin(), false) then
    if new."status" is distinct from old."status" then raise exception 'permission denied: only staff can change status'; end if;
    if new."total_price" is distinct from old."total_price" then raise exception 'permission denied: only staff can change total_price'; end if;
  end if;
  return new;
end $lock$;
drop trigger if exists "vc_lock_orders_money_status" on public."orders";
create trigger "vc_lock_orders_money_status" before update on public."orders" for each row execute function public."vc_lock_orders_money_status"();
