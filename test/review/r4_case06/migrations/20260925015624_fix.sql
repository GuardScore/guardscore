
create or replace function public."vc_lock_orders_money_status"() returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 and not coalesce(false, false) then
    if new."total_amount" is distinct from old."total_amount" then raise exception 'permission denied: only staff can change total_amount'; end if;
    if new."status" is distinct from old."status" then raise exception 'permission denied: only staff can change status'; end if;
  end if;
  return new;
end $lock$;
drop trigger if exists "vc_lock_orders_money_status" on public."orders";
create trigger "vc_lock_orders_money_status" before update on public."orders" for each row execute function public."vc_lock_orders_money_status"();

create or replace function public."vc_lock_profiles_role"() returns trigger language plpgsql as $lock$
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
drop trigger if exists "vc_lock_profiles_role" on public."profiles";
create trigger "vc_lock_profiles_role" before insert or update on public."profiles" for each row execute function public."vc_lock_profiles_role"();
