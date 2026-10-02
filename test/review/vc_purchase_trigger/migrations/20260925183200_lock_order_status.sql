-- Lock order status to prevent users from changing it
create or replace function public.vc_lock_orders_status() returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'INSERT' then
      new."status" := 'pending'::text;
    else
      if new."status" is distinct from old."status" then
        raise exception 'permission denied: only staff can change status';
      end if;
    end if;
  end if;
  return new;
end $lock$;

drop trigger if exists vc_lock_orders_status on public.orders;
create trigger vc_lock_orders_status before insert or update on public.orders
  for each row execute function public.vc_lock_orders_status();
