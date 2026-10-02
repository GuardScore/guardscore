-- Lock order total_amount to prevent users from changing it
create or replace function public.vc_lock_orders_total_amount() returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'UPDATE' then
      if new."total_amount" is distinct from old."total_amount" then
        raise exception 'permission denied: only staff can change total_amount';
      end if;
    end if;
  end if;
  return new;
end $lock$;

drop trigger if exists vc_lock_orders_total_amount on public.orders;
create trigger vc_lock_orders_total_amount before insert or update on public.orders
  for each row execute function public.vc_lock_orders_total_amount();
