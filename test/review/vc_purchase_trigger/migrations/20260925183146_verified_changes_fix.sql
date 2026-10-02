-- Fixes from Verified Changes (2026-09-25).
-- Each block was applied to a private copy of this database and re-checked: the attacks it
-- targets are blocked and the app's real users can still do what they did before.

-- orders: A user can set a quantity or amount on their own order to a negative number, which turns a purchase into a refund or credit.
-- PROVEN: applied to the private copy and re-checked: 1 finding(s) now blocked, real users on "orders" still work, nothing new leaks (when applied on its own)
alter table public."orders" add constraint "orders_total_amount_not_negative" check ("total_amount" >= 0) not valid;
-- "not valid" leaves existing rows alone; run "alter table ... validate constraint" once they're cleaned up
