
create or replace function public."vc_lock_invitations_role"() returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and new."role" is distinct from old."role" and old."invited_by" is distinct from auth.uid() then
    raise exception 'permission denied: only the sender can change an invitation''s role';
  end if;
  return new;
end $lock$;
drop trigger if exists "vc_lock_invitations_role" on public."invitations";
create trigger "vc_lock_invitations_role" before update on public."invitations" for each row execute function public."vc_lock_invitations_role"();

do $fix$ declare f record; d text; begin
  for f in select p.oid from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_language l on l.oid = p.prolang
    where n.nspname = 'public' and l.lanname = 'plpgsql' and 'team_id' = any(p.proargnames) and p.prosrc !~* 'variable_conflict' loop
    d := pg_get_functiondef(f.oid);
    d := regexp_replace(d, 'AS \$function\$', E'AS $function$\n#variable_conflict use_variable');
    execute d;
  end loop;
end $fix$;
