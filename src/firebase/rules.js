// Firestore rules → attack plan. PURE functions, fully unit-tested (no emulator):
// parse the rules into match blocks, enumerate the attacks worth running, and
// infer what to seed so a hole (if present) becomes observable. The emulator is
// the semantic oracle at run time (see verify.js); this file never decides
// allow/deny itself — it only decides WHAT to try and WHAT to plant.

const OWNER_FIELDS = ['uid', 'userid', 'user_id', 'owner', 'ownerid', 'owner_id', 'author', 'authorid', 'createdby', 'user'];
const SENSITIVE_PATH = /(^|\/)(users?|profiles?|accounts?|members?|messages?|chats?|conversations?|dms?|emails?|payments?|orders?|invoices?|subscriptions?|billing|private|secrets?|tokens?|notes?|journal|documents?|files?|health|medical)($|s?\/|\/)/i;

// Split a rules file into `match <path> { ... }` blocks with their allow lines.
export function parseRules(text) {
  const clean = String(text || '').replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
  const blocks = [];
  const re = /match\s+(\S+)\s+\{/g;
  let m;
  while ((m = re.exec(clean))) {
    const start = re.lastIndex;
    const rest = clean.slice(start);
    const end = rest.search(/\bmatch\b|\}/);
    const body = rest.slice(0, end < 0 ? rest.length : end);
    const allows = [...body.matchAll(/allow\s+([a-z,\s]+?)\s*:\s*if\s+([^;]+);/gi)]
      .map(a => ({ ops: a[1].replace(/\s/g, '').split(',').filter(Boolean), cond: a[2].trim().replace(/\s+/g, ' ') }));
    blocks.push({ path: m[1].trim(), allows });
  }
  return blocks;
}

// The collection segment an attack targets, e.g. "/users/{userId}" -> "users".
export function collectionOf(path) {
  const segs = String(path).split('/').filter(Boolean);
  // last collection segment (the one before the final {wildcard}, or the last literal)
  for (let i = segs.length - 1; i >= 0; i--) if (!segs[i].startsWith('{')) return segs[i];
  return segs[0] || 'docs';
}

// Detect the field a rule treats as the owner, for seeding a victim-owned doc.
export function ownerFieldOf(cond) {
  const m = /resource\.data\.(\w+)\s*==\s*request\.auth\.uid|request\.auth\.uid\s*==\s*resource\.data\.(\w+)/i.exec(cond || '');
  if (m) return m[1] || m[2];
  return 'uid';
}

const hasRead = ops => ops.some(o => /^(read|get|list)$/.test(o));
const hasWrite = ops => ops.some(o => /^(write|create|update|delete)$/.test(o));

// Privileged fields a document owner must NOT be able to set on their own doc
// (self-escalation) unless the rule pins them with request.resource.data.x == resource.data.x.
const PRIV_FIELD = /^(role|roles|isadmin|admin|is_admin|plan|tier|subscription|status|credits|balance|verified|is_verified|premium|entitlements?|permissions?|access_?level|owner|uid|user_?id)$/i;

// The leaf collection under a wildcard parent — the target of a collectionGroup query.
// e.g. /users/{u}/notes/{n} -> "notes" (a per-collection rule may not cover the group query).
export function subCollectionOf(path) {
  const segs = String(path).split('/').filter(Boolean);
  const cols = segs.filter(s => !s.startsWith('{'));
  return cols.length >= 2 ? cols[cols.length - 1] : null;
}

// Authority collections a rule trusts via get()/exists() for a role gate, paired
// with whether the app also lets a signed-in user WRITE that same collection —
// i.e. an attacker could provision their own authority doc and bypass the gate.
export function authorityGates(blocks) {
  const gates = new Set();
  for (const b of blocks) for (const a of b.allows) {
    const re = /(?:get|exists)\s*\(\s*\/databases\/[^/]+\/documents\/([a-zA-Z0-9_]+)\//gi;
    let m; while ((m = re.exec(a.cond))) gates.add(m[1]);
  }
  const writable = new Set();
  for (const b of blocks) {
    const col = collectionOf(b.path);
    const attackerWritable = b.allows.some(a => hasWrite(a.ops) && /request\.auth\s*!=\s*null|request\.auth\.uid/.test(a.cond) && !/resource\.data\.\w*(uid|owner|author)\w*\s*==\s*request\.auth\.uid/i.test(a.cond));
    const openWritable = b.allows.some(a => hasWrite(a.ops) && /^\(?\s*true\s*\)?$/i.test(a.cond));
    if (attackerWritable || openWritable) writable.add(col);
  }
  return [...gates].filter(g => writable.has(g));
}

// What to plant before attacking, so a hole is observable: a victim-owned doc
// and an attacker-owned doc in every collection, plus role/membership docs
// referenced by get()/exists() gates (for both actors) so both branches run.
export function seedPlan(blocks) {
  const docs = [];
  const memberships = [];
  for (const b of blocks) {
    const col = collectionOf(b.path);
    const owner = b.allows.map(a => ownerFieldOf(a.cond)).find(Boolean) || 'uid';
    docs.push({ collection: col, id: 'victim_doc', ownerField: owner, owner: 'victim' });
    docs.push({ collection: col, id: 'attacker_doc', ownerField: owner, owner: 'attacker' });
    for (const a of b.allows) {
      const g = /get\s*\(\s*\/databases\/[^/]+\/documents\/([a-zA-Z0-9_]+)\/\$\(\s*request\.auth\.uid\s*\)\s*\)\.data\.(\w+)/i.exec(a.cond);
      if (g) { memberships.push({ collection: g[1], field: g[2], forVictim: true }); memberships.push({ collection: g[1], field: g[2], forVictim: false, attackerWritable: null }); }
    }
  }
  return { actors: ['victim', 'attacker'], docs, memberships };
}

// The attacks to run: for each block, every actor×op that must be denied.
// `expect` is always 'deny' for these (they are attacks); the emulator decides
// what actually happens, and verify.js grades the two against each other.
export function attackSpecs(blocks) {
  const specs = [];
  const gates = authorityGates(blocks);           // M2: attacker-writable role gates
  for (const b of blocks) {
    const col = collectionOf(b.path);
    const owner = b.allows.map(a => ownerFieldOf(a.cond)).find(Boolean) || 'uid';
    const readable = b.allows.some(a => hasRead(a.ops));
    const writable = b.allows.some(a => hasWrite(a.ops));

    if (readable) {
      specs.push({ id: `${col}.anon.read`, class: 'anon_read', actor: 'anon', op: 'get', collection: col, doc: 'victim_doc', expect: 'deny', sensitive: SENSITIVE_PATH.test(b.path) });
      specs.push({ id: `${col}.cross.read`, class: 'cross_user_read', actor: 'attacker', op: 'get', collection: col, doc: 'victim_doc', expect: 'deny' });
      specs.push({ id: `${col}.cross.list`, class: 'list_leak', actor: 'attacker', op: 'list', collection: col, expect: 'deny' });
      specs.push({ id: `${col}.anon.list`, class: 'list_leak', actor: 'anon', op: 'list', collection: col, expect: 'deny' });
      // M2: collection-group query bypass on a subcollection under a wildcard parent.
      const sub = subCollectionOf(b.path);
      if (sub) specs.push({ id: `${sub}.group.read`, class: 'collection_group_bypass', actor: 'attacker', op: 'group_list', collection: sub, expect: 'deny' });
    }
    if (writable) {
      specs.push({ id: `${col}.anon.write`, class: 'anon_write', actor: 'anon', op: 'set', collection: col, doc: 'victim_doc', ownerField: owner, expect: 'deny' });
      specs.push({ id: `${col}.cross.write`, class: 'cross_user_write', actor: 'attacker', op: 'set', collection: col, doc: 'victim_doc', ownerField: owner, expect: 'deny' });
      // M2: field tampering — the owner sets a privileged field on their OWN doc.
      // The rule text can't be trusted to guard it; the emulator decides. We probe
      // the standard privileged fields so an unguarded update is proven.
      const guarded = b.allows.some(a => /request\.resource\.data\.(\w+)\s*==\s*resource\.data\.\1/i.test(a.cond));
      specs.push({ id: `${col}.tamper.priv`, class: 'field_tamper', actor: 'victim', op: 'tamper', collection: col, doc: 'victim_doc', field: 'role', guardedHint: guarded, expect: 'deny' });
    }
  }
  // M2: authority-gate bypass — attacker provisions a doc in a gate collection they
  // can write, then performs the gated op.
  for (const g of gates) specs.push({ id: `${g}.authority.bypass`, class: 'authority_bypass', actor: 'attacker', op: 'provision_then_act', collection: g, expect: 'deny' });

  const seen = new Set();
  return specs.filter(s => (seen.has(s.id) ? false : (seen.add(s.id), true)));
}

// Storage attacks (storage.rules, same grammar): can a stranger or another user
// read or overwrite a victim's object? A path with no owner binding on write, or
// public read of a personal path, is the storage analog of an open bucket.
const OPEN = /^\(?\s*true\s*\)?$/i;
const OWNER_IN_PATH = /request\.auth\.uid|resource\.metadata|\{userId\}|\{uid\}/i;
export function storageSpecs(blocks) {
  const specs = [];
  for (const b of blocks) {
    if (/\/b\/\{[^}]+\}\/o$/.test(b.path) && !b.allows.length) continue; // the /b/{bucket}/o wrapper
    const col = collectionOf(b.path);
    const readable = b.allows.some(a => a.ops.some(o => /^(read|get|list)$/.test(o)));
    const writable = b.allows.some(a => a.ops.some(o => /^(write|create|update|delete)$/.test(o)));
    const ownerBound = b.allows.some(a => OWNER_IN_PATH.test(a.cond) || OWNER_IN_PATH.test(b.path));
    if (readable) {
      specs.push({ id: `storage.${col}.anon.read`, class: 'storage_read', actor: 'anon', op: 'storage_get', collection: col, doc: 'victim_obj', expect: 'deny' });
      specs.push({ id: `storage.${col}.cross.read`, class: 'storage_read', actor: 'attacker', op: 'storage_get', collection: col, doc: 'victim_obj', expect: 'deny' });
    }
    if (writable && !ownerBound) {
      specs.push({ id: `storage.${col}.anon.write`, class: 'storage_write', actor: 'anon', op: 'storage_set', collection: col, doc: 'victim_obj', expect: 'deny' });
      specs.push({ id: `storage.${col}.cross.write`, class: 'storage_write', actor: 'attacker', op: 'storage_set', collection: col, doc: 'victim_obj', expect: 'deny' });
    }
  }
  const seen = new Set();
  return specs.filter(s => (seen.has(s.id) ? false : (seen.add(s.id), true)));
}

// The legitimate operations the victim MUST be able to do (else breaks_app).
export function legitSpecs(blocks) {
  const specs = [];
  for (const b of blocks) {
    const col = collectionOf(b.path);
    const owner = b.allows.map(a => ownerFieldOf(a.cond)).find(Boolean) || 'uid';
    if (b.allows.some(a => hasRead(a.ops))) specs.push({ id: `${col}.legit.read`, class: 'legit', actor: 'victim', op: 'get', collection: col, doc: 'victim_doc', expect: 'allow' });
    if (b.allows.some(a => hasWrite(a.ops))) specs.push({ id: `${col}.legit.write`, class: 'legit', actor: 'victim', op: 'set', collection: col, doc: 'victim_doc', ownerField: owner, expect: 'allow' });
  }
  const seen = new Set();
  return specs.filter(s => (seen.has(s.id) ? false : (seen.add(s.id), true)));
}
