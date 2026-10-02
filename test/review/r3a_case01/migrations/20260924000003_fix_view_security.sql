-- Fix view to respect RLS from underlying tables
ALTER VIEW order_history SET (security_invoker = true);
