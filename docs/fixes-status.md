# Fix status: what "proven" means, per class

Every finding ships a fix. Not every fix can be *proven* in the same way, and we label them honestly rather than implying more certainty than we have.

## Three levels

- **proven-on-copy** — the engine applies the fix to the private copy, re-runs the exact attack, and confirms it now fails while the owner's legitimate operations still pass. This is the strongest guarantee and the default for database-level fixes.
- **proven-by-construction** — the fix is a deterministic rule rewrite whose effect on the attack is not in question (e.g. replacing `allow read: if true` with an owner check makes the anonymous read deny). Used where re-running is redundant given the rule change.
- **advisory** — the hole, or its fix, lives in application code the engine cannot execute (an unauthenticated API route, a missing server-side check). We give the precise change to make; we cannot prove it from the database/rules alone, and we say so.

## Supabase (Postgres + RLS)

| Class | Fix level | Why |
|---|---|---|
| anon_read / anon_write | proven-on-copy | RLS/policy change re-attacked on the copy |
| cross_user_read / write, tenant leak | proven-on-copy | re-attacked as the other user after the fix |
| self_grant_admin, privileged_tamper | proven-on-copy | `with check` / column guard re-attacked |
| public_bucket, storage_* | proven-on-copy | bucket/policy change re-attacked |
| definer_exposed / rpc_leak | proven-on-copy where the fix is a grant/revoke or `security invoker`; **advisory** when the function body itself must change | some require editing SQL the author owns |
| service_key_exposed (leaked secret) | **advisory** | the fix is rotate + move to server env — outside the database |

The `fix` command applies and re-proves the database fixes and reports which remain for a person (`still needs a person: …`). That list is the advisory set, labeled as such — not hidden.

## Firebase (rules)

All rule fixes are **proven-by-construction** today (owner-scoping, field-pinning, collection-group coverage, locking an authority collection). The natural next step, once the emulator run is wired (`npm run firebase:check`), is to promote them to **proven-on-copy**: apply the fixed rule in the emulator and re-attack, exactly as the Supabase engine does. The hook is in place; it needs the emulator to execute.

## Prisma

**Advisory only, by nature.** Prisma access control is application-layer; a static read of `schema.prisma` cannot prove an authz fix. The advisor says what to add (owner/tenant scoping, RLS in a migration) and points you to the Postgres engine to prove the SQL side. It never returns "safe".

## The honest headline

Database and rules fixes are proven (on-copy for Supabase, by-construction for Firebase, on-copy for Firebase once the emulator run is on). Fixes that live in application code or in secret rotation are advisory and always labeled — we never claim to have proven a change we cannot execute.
