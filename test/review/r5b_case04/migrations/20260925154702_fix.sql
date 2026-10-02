
create or replace function public."lock_profiles_role"() returns trigger language plpgsql as $lock$
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
drop trigger if exists "lock_profiles_role" on public."profiles";
create trigger "lock_profiles_role" before insert or update on public."profiles" for each row execute function public."lock_profiles_role"();
