
create or replace function public."vc_lock_orders_money_status"() returns trigger language plpgsql as $lock$
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
drop trigger if exists "vc_lock_orders_money_status" on public."orders";
create trigger "vc_lock_orders_money_status" before insert or update on public."orders" for each row execute function public."vc_lock_orders_money_status"();

alter table public."products" enable row level security;
revoke all on table public."products" from anon;

create or replace function public."vc_lock_reviews_money_status"() returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 and not coalesce(false, false) then
    if tg_op = 'INSERT' then
      new."is_approved" := true;
      new."helpful_count" := 0;
    else
      if new."is_approved" is distinct from old."is_approved" then raise exception 'permission denied: only staff can change is_approved'; end if;
      if new."helpful_count" is distinct from old."helpful_count" then raise exception 'permission denied: only staff can change helpful_count'; end if;
    end if;
  end if;
  return new;
end $lock$;
drop trigger if exists "vc_lock_reviews_money_status" on public."reviews";
create trigger "vc_lock_reviews_money_status" before insert or update on public."reviews" for each row execute function public."vc_lock_reviews_money_status"();
