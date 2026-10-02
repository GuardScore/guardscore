# Firebase attack engine — design spec

Status: spec (not yet built). Target: parity with the Supabase engine (`src/verify.js` + `src/gauntlet.js`) — a real, emulated backend that we *attack*, not a rules linter. Same Guard Score rubric, same verdict vocabulary, same false-alarm discipline.

The static `web/firebase-scan.js` (already shipped) is the instant front-door pre-check. This document is the deep engine that stands behind it — the Firebase analog of what makes the Supabase engine the most accurate tool tested.

---

## 1. Why an emulator, not a parser

Firestore rules are a small language with runtime-only behavior a text scan cannot resolve:

- `get()` / `exists()` cross-document lookups whose result depends on *seeded data*, not on the rule text.
- `request.auth.token` custom claims that only exist once a user is minted with them.
- `list` vs `get` divergence: a rule can allow reading one document by ID but leak the whole collection under a query, or vice-versa.
- Collection-group queries (`collectionGroup('x')`) that bypass per-collection `match` blocks the author reasoned about in isolation.
- `request.resource.data` vs `resource.data` — write rules that validate the *incoming* doc but not the *existing* one (or the reverse), enabling field tampering.

The only faithful oracle for "can attacker A do operation O on path P" is the real rules VM with real data behind it. Google ships exactly that: the **Firestore emulator** (part of `firebase-tools`, runs the production rules engine on the JVM). We drive it the same way the Supabase engine drives PGlite/Postgres: build a private copy, seed known actors, attack, confirm legitimate users still work.

---

## 2. Architecture

```
project sources                      engine (this spec)
────────────────                     ──────────────────
firebase.json          ─┐
firestore.rules         ├─► loader ─► emulator harness ─► gauntlet ─► scorer ─► report
storage.rules           │            (Firestore+Auth+     (attack     (Guard
firestore.indexes.json ─┘             Storage emulators)   classes)    Score)
```

### 2.1 Emulator harness (`src/firebase/emulator.js`)

Mirrors the role of PGlite bootstrapping in `src/verify.js`.

- **Runtime dependency:** `firebase-tools` (Apache-2.0 — permissive, shippable) and a JRE (the Firestore/Storage emulators are Java). The JRE is the one heavy prerequisite; document it and detect it (`java -version`) with a clear error, exactly as we detect the Postgres binary today.
- **Start:** launch `firebase emulators:start --only firestore,auth,storage --project guardscore-<rand>` on ephemeral ports, `import`-less (empty), with rules pointed at the project's `firestore.rules` / `storage.rules`. Parse the emulator hub JSON to discover assigned ports rather than assuming defaults.
- **Isolation:** one emulator instance per verification, unique project id, temp working dir, killed in `finally`. No shared state between runs — the Supabase engine's hard rule.
- **Reset between attack phases:** use the emulator's `DELETE /emulator/v1/projects/<id>/databases/(default)/documents` to wipe, so each attack starts from the same seeded baseline. Re-seed via the admin channel (below) between phases where an attack mutates data.

### 2.2 Two channels, like anon vs service_role

The Supabase engine distinguishes the privileged seed path (service role, bypasses RLS) from the attack path (anon / impersonated JWT, subject to RLS). Firestore's equivalents:

- **Admin channel (seeding, ground truth):** talk to the emulator with the Admin SDK / REST using the emulator's admin bypass (`Authorization: Bearer owner`, or the Admin SDK pointed at `FIRESTORE_EMULATOR_HOST`). Rules do **not** apply. This is how we plant known documents and read ground truth to grade attacks.
- **Client channel (attack surface):** talk to the same database through the **client** REST API (`https://firestore.googleapis.com/v1/...` shape, but against the emulator host) with a real ID token, or with **no** token for the anonymous attacker. Rules **do** apply. This is the attacker's view.

### 2.3 Seeding actors (`src/firebase/seed.js`)

Analog of seeding two users + rows in the Supabase gauntlet.

Mint, via the **Auth emulator** REST (`/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake`):

- `victim` — uid `V`, email `victim@…`.
- `attacker` — uid `A`, email `attacker@…`.
- Optionally `admin` — uid `M`, minted **with** whatever custom claims the rules reference (see 4.7). Custom claims are set through the Auth emulator's `setCustomUserClaims` equivalent, then a fresh ID token is fetched so `request.auth.token.<claim>` is populated.

Each returns an ID token we attach on the client channel. The anonymous attacker sends no `Authorization` header.

**Data seeding is inferred from the rules, not from app knowledge.** For every `match /col/{id}` block, plant (via admin channel):
- one doc owned by `victim` (owner field populated for whichever of `uid|user|userId|owner|author|ownerId` the rule reads),
- one doc owned by `attacker`,
- where a rule references `get(/databases/$(db)/documents/<other>/$(x))`, plant the referenced membership/role docs for both actors so both the "member" and "non-member" branches are exercised.

The seeder's job is to create the *conditions under which a hole, if present, becomes observable* — the same reason the Supabase gauntlet inserts a victim row before trying to read it as the attacker.

---

## 3. Verdict vocabulary (unchanged)

Reuse the Supabase engine's five verdicts verbatim so scores are comparable across stacks:

| verdict | meaning |
|---|---|
| `unsafe` | an attacker (anon or another signed-in user) performed a read/write they must not — **proven** by the emulator |
| `breaks_app` | a legitimate owner was denied a read/write they must be able to do (over-tight rules / lockout) |
| `incomplete` | the rules protect some paths but leave a sibling/subcollection/collection-group route open |
| `untested` | a path exists but the engine could not construct a decisive attack (record it; never score it as safe) |
| `safe` | every attack was correctly denied **and** every legitimate operation was allowed |

---

## 4. Attack classes

Each class is an assertion of the form *actor → operation → path → expected deny/allow*, executed on the client channel and graded against the admin-channel ground truth. Mapped from the Supabase gauntlet's ~29 classes to Firestore semantics.

### 4.1 `anon_read` / `anon_write`
Anonymous client (no token) attempts `GET /documents/<col>/<victimDoc>` and `PATCH`/`DELETE`/create. Any success is `unsafe`. Direct analog of Supabase anon read/write. Covers the `allow read, write: if true` and test-mode cases the static scanner flags — here **confirmed** by a real request.

### 4.2 `cross_user_read` / `cross_user_write`
`attacker` token reads/writes `victim`'s document. Success where the rule intended owner-scoping is `unsafe`. This is the highest-value class — it catches the subtly-wrong ownership check (`resource.data.uid == request.auth.uid` written as `request.resource.data.uid == request.auth.uid`, so an attacker sets the field on the way in and "owns" any write).

### 4.3 `list_leak` (list vs get divergence)
Rule allows `get` on a doc by id but the collection also permits `list`; attacker issues a **query** (`runQuery` / `list`) with no owner filter and receives other users' docs. Firestore evaluates `list` against the rule with `resource` = *each candidate doc*, so an owner-scoped `read` rule that references `resource.data.uid == request.auth.uid` actually *does* constrain lists — but a rule gated only on `request.auth != null` leaks the whole collection to any signed-in user. Grade by whether the attacker's query returns any doc owned by `victim`.

### 4.4 `collection_group_bypass`
If any subcollection name is reused (e.g. `/users/{u}/notes/{n}` and the app elsewhere does `collectionGroup('notes')`), attempt a `collectionGroup` query as `attacker`. Per-collection `match` blocks do **not** automatically cover collection-group reads unless a `match /{path=**}/notes/{n}` rule exists. Returning victim docs is `unsafe`; this is a class text scanners essentially never catch.

### 4.5 `get_exists_bypass`
For rules gated on `get(/…/members/$(request.auth.uid)).data.role == 'x'` or `exists(...)`: seed the attacker **without** the membership doc and confirm deny; then seed **with** an attacker-controlled membership doc (if the membership collection is itself writable by the attacker — check that path's write rule) and confirm the gate is now bypassable. A role gate that reads from a collection the attacker can write to is `unsafe` (privilege escalation through a writable authority table).

### 4.6 `field_tamper` (privileged field write)
`attacker` (as legitimate owner of *their own* doc) attempts to `PATCH` a sensitive field the rule fails to protect on update — e.g. `plan`, `tier`, `role`, `credits`, `isAdmin`, `verified`. Firestore rules must guard these with `request.resource.data.<f> == resource.data.<f>` (unchanged) on update; absence means the owner can self-upgrade. Analog of the Supabase `privileged_tamper` / plan-upgrade class (the one that required the `BASE_TIER` fix). Grade by reading the field back via admin channel after the write.

> **Out of scope (safety constraint, carried over verbatim from the Supabase engine):** the signup-/invite-metadata role-escalation class — where a user sets a privileged field *at account creation* through auth metadata — is **excluded**. Do not construct, seed, or emit attack code for it. `field_tamper` here is strictly post-creation document writes to an existing doc the actor already owns.

### 4.7 `custom_claim_gap`
Where rules trust `request.auth.token.<claim>` (e.g. `admin == true`): confirm `attacker` (minted without the claim) is denied, and that the gate genuinely depends on the claim (mint `admin` *with* it, confirm allow). This validates the gate is real, not that we can forge claims — we cannot mint claims we aren't given; forging is not an attack we simulate. Result is `safe` for that path if deny holds; the value is distinguishing a real claim gate from an `if request.auth != null` masquerading as one.

### 4.8 Storage classes (`storage_read` / `storage_write` / `public_object`)
Against the **Storage emulator** with `storage.rules`:
- anon and `attacker` attempt `GET`/`PUT`/`DELETE` on an object path seeded under `victim` (e.g. `user/{V}/…`). Success is `unsafe`.
- `allow read, write: if true` or `if request.auth != null` (no owner/path binding) on a personal path → confirmed leak. Analog of Supabase `storage_*` and `public_bucket`.

### 4.9 Callable / HTTPS functions — **deferred, explicitly**
Cloud Functions are arbitrary code, not declarative rules; emulating them faithfully means running the user's function code (heavy, and a much larger trust surface). v1 of the engine scopes functions to a **static** note only ("N callable functions detected — not yet attacked"), never a `safe`. Revisit as a separate milestone; do not let the score imply functions were checked.

---

## 5. Legitimate-use confirmation (the half that stops false positives)

Every Supabase verdict is paired with a check that the *owner* can still do their job — this is what separates us from scanners that flag `if request.auth != null` as always-bad. For Firestore:

- After asserting an attack is denied, assert the **owner** succeeds: `victim` reads/writes/queries their own docs and objects.
- If the owner is *also* denied, the finding downgrades from `unsafe`/`incomplete` to `breaks_app` (over-tight), which caps the score differently (§6) and produces a different fix.
- A rule that denies everyone (`allow read, write: if false` on a collection the app clearly uses) is `breaks_app`, not `safe` — the same lockout logic as Supabase RLS-with-no-policies.

---

## 6. Scoring (identical rubric)

Reuse the Supabase caps so a Guard Score means the same thing on any stack:

```
raw = 100 − Σ penalty(finding)
guardScore =
  leaked.length ? min(raw, 59)      // any proven attacker read/write
  : broken.length ? min(raw, 79)    // legitimate user blocked
  : raw                             // else up to 100
```

- `unsafe` findings populate `leaked` (hard cap 59).
- `breaks_app` populate `broken` (cap 79).
- `incomplete` penalize but do not cap below 60 on their own unless a concrete leak was proven on the open sibling path.
- `untested` never raises the score and is surfaced as an explicit "not proven" line, never hidden.

---

## 7. Integration surface

Mirror the existing engine so the CLI/MCP/API don't special-case stacks:

- `src/firebase/verify.js` exports `verifyFirebase({ projectDir })` returning the **same report shape** as `src/verify.js` (`{ guardScore, verdict, findings:[{severity,class,table,what,fix,proof}], counts, stack:'firebase' }`). `table` carries the Firestore path.
- Stack detection in the loader: `firestore.rules` / `firebase.json` present → Firebase engine; `supabase/migrations/*.sql` → Supabase engine. This is the "Lighthouse, one score, per-stack engine" contract from the front door made real on the backend.
- `proof` field (new, additive — also worth backporting to Supabase): the literal request + response that demonstrates the hole (`attacker GET /users/V → 200 {email:…}`), so a finding is reproducible, not asserted. This is the credibility multiplier for going viral: every red line comes with the receipt.
- Each attack class ships with a paired test app (safe variant + vulnerable variant) under `apps/firebase/*`, scored by a held-out blind eval exactly like the Supabase `final.tsv` harness. Ship no engine change without the blind number moving the right way.

---

## 8. Hard parts (call them out, don't discover them in prod)

1. **JRE dependency.** The Firestore/Storage emulators need Java. This is the biggest UX tax vs. the pure-Node Supabase path. Options: (a) detect + clear install message; (b) offer a hosted mode where we run the emulator server-side and the CLI streams rules up. Decide before shipping — it shapes the "easy to use" claim.
2. **Emulator startup latency** (~2–5 s JVM warm-up). Pool a warm emulator per session like the Supabase warm-pool, or accept the cost on cold runs. Never let it push users toward skipping the deep check.
3. **`list` grading is subtle.** Firestore denies a query if *any* candidate doc fails the rule, so an owner-scoped read rule makes an unfiltered `list` fail for the attacker (correct) — but the attacker can add the owner filter with *their own* uid and get nothing, which is safe, vs. a `request.auth != null` rule where an unfiltered list succeeds and leaks. Grade on "did victim-owned docs come back," not on "did the query error."
4. **`request.resource` vs `resource` on update.** The tamper class must issue a real partial update against a real existing doc; constructing the update payload so only the target field changes is what makes the finding decisive. Get this wrong and you get false `breaks_app`.
5. **Rules `function` helpers and `match` nesting.** Parse enough structure to know which paths are reachable and which helpers gate them, but let the *emulator* be the semantic oracle — never re-implement rule evaluation (that road is where the false alarms live). The parser's only job is to enumerate attackable paths and seed hints.
6. **No forging.** We attack with capabilities a real attacker has (no token, another real token, writes to collections that are writable). We never fabricate custom claims we weren't granted or spoof another uid's token — those aren't real-world attacks and would produce findings that don't reproduce.

---

## 9. Milestones

1. Emulator harness + two-channel seeding + `anon_read/write` and `cross_user_read/write` (covers the majority of real vibecoded Firestore holes).
2. `list_leak` + `collection_group_bypass` + `field_tamper` (the classes scanners miss — our differentiation).
3. Storage classes.
4. Blind eval corpus (`apps/firebase/*`, held-out labels) + score parity gate.
5. `proof` receipts (backport to Supabase too).
6. (Later) callable-function attacking; hosted/JRE-free mode.

Ship order matches the Supabase engine's: get the slam-dunk classes proven and benchmarked first, add the scanner-beating classes second, keep every step honest with a blind number.
