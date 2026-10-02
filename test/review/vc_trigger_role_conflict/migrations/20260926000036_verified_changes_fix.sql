-- Fixes from Verified Changes (2026-09-26).
-- Each block was applied to a private copy of this database and re-checked: the attacks it
-- targets are blocked and the app's real users can still do what they did before.

-- accept_invitation: A database function used by the access rules fails with "column reference invitation_code is ambiguous": its parameter has the same name as a column, so every query that runs it errors.
-- PROVEN: applied to the private copy and re-checked: 1 finding(s) now blocked, real users on "accept_invitation" still work, nothing new leaks
do $fix$ declare f record; d text; begin
  for f in select p.oid from pg_proc p join pg_namespace n on n.oid = p.pronamespace join pg_language l on l.oid = p.prolang
    where n.nspname = 'public' and l.lanname = 'plpgsql' and 'invitation_code' = any(p.proargnames) and p.prosrc !~* 'variable_conflict' and p.prosrc !~* 'on\s+conflict' and p.proname in ('accept_invitation') loop
    d := pg_get_functiondef(f.oid);
    d := regexp_replace(d, 'AS \$function\$', E'AS $function$\n#variable_conflict use_variable');
    execute d;
  end loop;
end $fix$;
