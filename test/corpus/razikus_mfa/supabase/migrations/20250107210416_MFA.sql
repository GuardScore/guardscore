create schema if not exists "authenticative";

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION authenticative.is_user_authenticated()
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
AS $function$
  SELECT array[(select auth.jwt()->>'aal')] <@ (
    SELECT
      CASE
        WHEN count(id) > 0 THEN array['aal2']
        ELSE array['aal1', 'aal2']
      END as aal
    FROM auth.mfa_factors
    WHERE (auth.uid() = user_id)
    AND status = 'verified'
  );
$function$
;

