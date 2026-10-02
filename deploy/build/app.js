/* ---------- static scanner (mirror of web/scan.js, guarded by test/web-scan.js) ---------- */
const EXPLAIN={anon_read:"Anyone on the internet, without logging in, can read this table.",anon_write:"Anyone on the internet, without logging in, can change or delete rows in this table.",public_bucket:"A storage bucket whose name says it holds private files is public: anyone with a file's URL can download it, whatever the storage policies say.",rls_lockout:"Row level security is on but the table has no policies, so no ordinary user can read or write it — this locks your own app out unless every access goes through the service role."};
const FIX={no_rls:t=>`Enable row level security and add owner-scoped policies:\n  alter table ${t} enable row level security;\n  create policy "${t}_own" on ${t} for all to authenticated\n    using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));`,allow_all_read:t=>`Replace the always-true read rule with an owner check:\n  using ( user_id = (select auth.uid()) )`,allow_all_write:t=>`Replace the always-true write rule with an owner check:\n  using ( user_id = (select auth.uid()) ) with check ( user_id = (select auth.uid()) )`,public_bucket:b=>`Make the bucket private and serve files through signed URLs:\n  update storage.buckets set public = false where id = '${b}';`,rls_lockout:t=>`Add the policies your app needs, e.g. an owner policy:\n  create policy "${t}_own" on ${t} for all to authenticated using (user_id = (select auth.uid()));`};
function statements(sql){let s=String(sql||"");s=s.replace(/--[^\n]*/g," ").replace(/\/\*[\s\S]*?\*\//g," ");const out=[];let buf="",i=0,dollar=null,inStr=false;while(i<s.length){const c=s[i];if(dollar){if(s.startsWith(dollar,i)){buf+=dollar;i+=dollar.length;dollar=null;continue}buf+=c;i++;continue}if(inStr){buf+=c;if(c==="'"){if(s[i+1]==="'"){buf+="'";i+=2;continue}inStr=false}i++;continue}if(c==="'"){inStr=true;buf+=c;i++;continue}const dq=/^\$[a-zA-Z_]*\$/.exec(s.slice(i));if(dq){dollar=dq[0];buf+=dollar;i+=dollar.length;continue}if(c===";"){if(buf.trim())out.push(buf.trim());buf="";i++;continue}buf+=c;i++}if(buf.trim())out.push(buf.trim());return out}
const schemaOf=n=>{const m=/^"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s*\./.exec(String(n||""));return m?m[1].toLowerCase():"public"};
const norm=n=>String(n||"").replace(/"/g,"").replace(/^public\./i,"").toLowerCase();
const SENSITIVE_COL=/(^|_)(email|phone|mobile|address|full_name|first_name|last_name|ssn|dob|date_of_birth|national_id|passport|password|password_hash|secret|api_key|access_token|refresh_token|stripe_\w+|card_\w+|iban|token)$/i;
const PRIVATE_BUCKET=/id_?cards?|docs?|documents?|invoices?|receipts?|private|secure|contracts?|passports?|medical|reports?|backups?|exports?|attachments?|uploads?|files?/i;
const SERVER_TABLE=/(^|_)(oauth|token|tokens|credential|secret|webhook|stripe|billing|integration|sync|audit|log|logs|event|events|migration|schema_migration|cron|queue|outbox)(_|s|$)/i;
function staticScan(sql){
  const stmts=statements(sql);const tables={};const table=n=>(tables[n]||={name:n,cols:new Set(),rls:false,policies:[]});const buckets={};const objectPolicies=[];
  for(const st of stmts){const low=st.toLowerCase();let m=/^create\s+table\s+(?:if\s+not\s+exists\s+)?([^\s(]+)\s*\(([\s\S]*)\)/i.exec(st);
    if(m){const name=norm(m[1]);if(schemaOf(m[1])!=="public")continue;const t=table(name);const body=m[2];let depth=0,cur="",cols=[];for(const ch of body){if(ch==="(")depth++;else if(ch===")")depth--;if(ch===","&&depth===0){cols.push(cur);cur=""}else cur+=ch}if(cur.trim())cols.push(cur);for(const c of cols){const cm=/^\s*"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s+/.exec(c);if(!cm)continue;const cn=cm[1].toLowerCase();if(/^(constraint|primary|foreign|unique|check|exclude|like)$/i.test(cn))continue;t.cols.add(cn)}continue}
    m=/^alter\s+table\s+(?:if\s+exists\s+)?([^\s]+)\s+enable\s+row\s+level\s+security/i.exec(st);if(m){if(schemaOf(m[1])==="public")table(norm(m[1])).rls=true;continue}
    m=/^create\s+policy\s+("(?:[^"]|"")*"|\S+)\s+on\s+([^\s]+)([\s\S]*)$/i.exec(st);
    if(m){const on=norm(m[2]);const isStorage=/storage\s*\.\s*objects/i.test(m[2])||on==="objects";if(!isStorage&&schemaOf(m[2])!=="public")continue;const rest=m[3];const cmd=(/\bfor\s+(select|insert|update|delete|all)\b/i.exec(rest)||[,"all"])[1].toLowerCase();const roles=(/\bto\s+([a-z_,\s"]+?)(?=\s+(using|with)\b|$)/i.exec(rest)||[,""])[1].toLowerCase();const using=(/\busing\s*\(([\s\S]*?)\)\s*(with\s+check|$)/i.exec(rest)||[,""])[1];const check=(/\bwith\s+check\s*\(([\s\S]*)\)\s*$/i.exec(rest)||[,""])[1];const pol={cmd,roles,using:using.trim(),check:check.trim(),restrictive:/\bas\s+restrictive\b/i.test(rest)};if(isStorage)objectPolicies.push(pol);else table(on).policies.push(pol);continue}
    if(/insert\s+into\s+storage\s*\.\s*buckets/i.test(low)){const cm=/\(([^)]*)\)\s*values?\s*([\s\S]*)/i.exec(st);if(cm){const colNames=cm[1].split(",").map(x=>x.trim().replace(/"/g,"").toLowerCase());const pubIdx=colNames.indexOf("public");const tuples=cm[2].match(/\(([^)]*)\)/g)||[];for(const tup of tuples){const vals=tup.slice(1,-1).split(",").map(x=>x.trim());const idIdx=colNames.indexOf("id");const id=idIdx>=0&&vals[idIdx]?vals[idIdx].replace(/^'|'$/g,""):(vals[0]||"").replace(/^'|'$/g,"");const isPublic=pubIdx>=0?/true/i.test(vals[pubIdx]||""):false;if(id)buckets[id]={public:isPublic}}}}
  }
  const isTrue=x=>/^\s*\(?\s*true\s*\)?\s*$/i.test(x||"");const anonPol=r=>!r.trim()||/\banon\b/.test(r)||/\bpublic\b/.test(r);
  const findings=[];const add=(sev,cls,tbl,what,fix)=>findings.push({severity:sev,class:cls,table:tbl,what,fix});const sensitive=t=>[...t.cols].some(c=>SENSITIVE_COL.test(c));
  for(const t of Object.values(tables)){let anonRead=false,anonWrite=false;
    for(const p of t.policies){if(p.restrictive||!anonPol(p.roles))continue;if((p.cmd==="select"||p.cmd==="all")&&isTrue(p.using))anonRead=true;if((p.cmd==="update"||p.cmd==="delete"||p.cmd==="all")&&(isTrue(p.using)||isTrue(p.check)))anonWrite=true;if(p.cmd==="insert"&&isTrue(p.check))anonWrite=true}
    const noRls=!t.rls&&!t.policies.length&&!SERVER_TABLE.test(t.name);
    if(anonWrite)add("critical","anon_write",t.name,EXPLAIN.anon_write,FIX.allow_all_write(t.name));
    if(anonRead)sensitive(t)?add("critical","anon_read",t.name,"Anyone, without logging in, can read this table — and it holds personal data (email, phone or similar).",FIX.allow_all_read(t.name)):add("warning","anon_read",t.name,"This table looks readable by anyone without logging in. Fine for a public catalog or leaderboard, a leak otherwise — the full verifier confirms by attacking it.",FIX.allow_all_read(t.name));
    if(noRls&&!anonWrite&&!anonRead){if(sensitive(t))add("critical","anon_write",t.name,"Row level security is off on this table and it holds personal data, so anyone the database exposes it to can read or change it.",FIX.no_rls(t.name));else add("warning","rls_lockout",t.name,"Row level security is not enabled on this table. If Supabase exposes it to the anon role (the default for public tables), anyone can read and write it — the full verifier confirms.",FIX.no_rls(t.name))}
    else if(t.rls&&!t.policies.length&&!SERVER_TABLE.test(t.name))add("warning","rls_lockout",t.name,EXPLAIN.rls_lockout,FIX.rls_lockout(t.name));
  }
  for(const[id,b]of Object.entries(buckets))if(b.public&&PRIVATE_BUCKET.test(id))add("high","public_bucket",`storage: ${id}`,EXPLAIN.public_bucket,FIX.public_bucket(id));
  const seen=new Set();const uniq=findings.filter(f=>{const k=f.class+"|"+f.table;if(seen.has(k))return false;seen.add(k);return true});const order={critical:0,high:1,warning:2};uniq.sort((a,b)=>order[a.severity]-order[b.severity]);
  const crit=uniq.filter(f=>f.severity==="critical"||f.severity==="high").length;const warn=uniq.filter(f=>f.severity==="warning").length;const tableCount=Object.keys(tables).length;
  let guardScore;if(crit)guardScore=Math.max(12,59-8*(crit-1));else if(warn)guardScore=Math.max(70,79-3*(warn-1));else guardScore=100;
  return{guardScore,verdict:crit?"unsafe":warn?"review":tableCount?"clear":"empty",tableCount,counts:{critical:uniq.filter(f=>f.severity==="critical").length,high:uniq.filter(f=>f.severity==="high").length,warning:warn},findings:uniq}
}

/* ---------- Firestore rules scanner (mirror of web/firebase-scan.js, guarded by test/web-firebase-scan.js) ---------- */
function firestoreScan(rulesText){
  const text=String(rulesText||"");
  const SENS=/(^|\/)(users?|profiles?|accounts?|members?|messages?|chats?|conversations?|dms?|emails?|payments?|orders?|invoices?|subscriptions?|billing|private|secrets?|tokens?|notes?|journal|documents?|files?|health|medical)($|s?\/|\/)/i;
  const OPEN=/^\(?\s*true\s*\)?$/i;
  const OWNER=/request\.auth\.uid\s*==|==\s*request\.auth\.uid|resource\.data\.\w*(uid|user|owner|author)\w*\s*==\s*request\.auth\.uid/i;
  const AUTHED=/request\.auth\s*!=\s*null|request\.auth\.uid|request\.auth\s*\.\s*token/;
  const GATED=/get\s*\(|exists\s*\(|hasrole|has_role|role\s*==|admin|isadmin/i;
  const FEX={open_write:"Anyone on the internet, without signing in, can create, change, or delete documents here (allow write: if true).",open_read:"Anyone on the internet, without signing in, can read every document here (allow read: if true).",any_signed_in_write:"Any signed-in user can write documents here — the rule checks that someone is logged in, not that the document is theirs, so one user can overwrite another’s."};
  const FFX={open_write:p=>`Scope writes to the document’s owner:\n  match ${p} {\n    allow write: if request.auth != null && request.auth.uid == resource.data.uid;\n  }`,open_read:p=>`Scope reads to the owner (or a membership check):\n  match ${p} {\n    allow read: if request.auth != null && request.auth.uid == resource.data.uid;\n  }`,any_signed_in_write:p=>`Add an owner check to the write rule:\n  allow write: if request.auth != null && request.auth.uid == resource.data.uid;`};
  const clean=text.replace(/\/\/[^\n]*/g,"").replace(/\/\*[\s\S]*?\*\//g,"");
  const blocks=[];const re=/match\s+(\S+)\s+\{/g;let m;
  while((m=re.exec(clean))){const start=re.lastIndex;const rest=clean.slice(start);const end=rest.search(/\bmatch\b|\}/);const body=rest.slice(0,end<0?rest.length:end);const allows=[...body.matchAll(/allow\s+([a-z,\s]+?)\s*:\s*if\s+([^;]+);/gi)].map(a=>({ops:a[1].replace(/\s/g,"").split(",").filter(Boolean),cond:a[2].trim().replace(/\s+/g," ")}));blocks.push({path:m[1].trim(),allows});}
  const findings=[];const add=(s,c,p,w,f)=>findings.push({severity:s,class:c,table:p,what:w,fix:f});
  const total=blocks.reduce((n,b)=>n+b.allows.length,0);
  for(const b of blocks){for(const{ops,cond}of b.allows){const write=ops.some(o=>/^(write|create|update|delete)$/.test(o));const read=ops.some(o=>/^(read|get|list)$/.test(o));
    if(OPEN.test(cond)){if(write)add("critical","open_write",b.path,FEX.open_write,FFX.open_write(b.path));if(read)SENS.test(b.path)?add("critical","open_read",b.path,"Anyone, without signing in, can read every document here — and the path looks like personal data.",FFX.open_read(b.path)):add("warning","open_read",b.path,"This path looks readable by anyone without signing in. Fine for public content, a leak otherwise — the full engine confirms by attacking it.",FFX.open_read(b.path));}
    else if(write&&AUTHED.test(cond)&&!OWNER.test(cond)&&!GATED.test(cond))add("warning","any_signed_in_write",b.path,FEX.any_signed_in_write,FFX.any_signed_in_write(b.path));}}
  if(/allow\s+read,\s*write\s*:\s*if\s+request\.time\s*<\s*timestamp/i.test(text))add("critical","open_write","/{document=**}","These rules are in test mode — the whole database is open to anyone until a set date.","Replace the test-mode rule with real per-collection owner rules before launch.");
  if(!blocks.length&&text.trim())add("warning","rules_missing","(rules)","No match blocks were found in these rules. Confirm this is really your firestore.rules file.","Add per-collection rules scoped to request.auth.uid.");
  const seen=new Set();const uniq=findings.filter(f=>{const k=f.class+"|"+f.table;if(seen.has(k))return false;seen.add(k);return true});const order={critical:0,high:1,warning:2};uniq.sort((a,b)=>order[a.severity]-order[b.severity]);
  const crit=uniq.filter(f=>f.severity==="critical"||f.severity==="high").length;const warn=uniq.filter(f=>f.severity==="warning").length;
  let guardScore;if(crit)guardScore=Math.max(12,59-8*(crit-1));else if(warn)guardScore=Math.max(70,79-3*(warn-1));else guardScore=100;
  return{stack:"firebase",guardScore,verdict:crit?"unsafe":warn?"review":total?"clear":"empty",tableCount:blocks.length,counts:{critical:uniq.filter(f=>f.severity==="critical").length,high:uniq.filter(f=>f.severity==="high").length,warning:warn},findings:uniq};
}

const DEMO_SUPABASE=`-- JournalAI — AI journaling app, built in an afternoon
create table public.profiles (
  id uuid primary key references auth.users,
  email text,
  display_name text,
  plan text default 'free'
);
-- (row level security never enabled on profiles)

create table public.entries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  title text,
  body text,
  created_at timestamptz default now()
);
alter table public.entries enable row level security;
create policy "enable access for all" on public.entries
  for all using (true) with check (true);

create table public.subscriptions (
  id uuid primary key,
  user_id uuid,
  status text,
  stripe_customer_id text
);
alter table public.subscriptions enable row level security;
create policy "read subscriptions" on public.subscriptions
  for select using (true);

insert into storage.buckets (id, name, public)
  values ('documents', 'documents', true);`;

const DEMO_FIRESTORE=`rules_version = '2';
// ChatMate — a group chat app, shipped over a weekend
service cloud.firestore {
  match /databases/{database}/documents {

    match /users/{userId} {
      // meant to be "only you can edit your profile" — but nobody checked
      allow read, write: if true;
    }

    match /messages/{messageId} {
      allow read: if request.auth != null;
      // any signed-in user can edit or delete anyone's message
      allow write: if request.auth != null;
    }

    match /payments/{paymentId} {
      allow read: if true;
      allow write: if request.auth != null && request.auth.uid == resource.data.uid;
    }
  }
}`;

let stack='supabase';
const STACKS={
  supabase:{scan:staticScan, demo:DEMO_SUPABASE, name:'Supabase', path:'supabase/migrations/*.sql', ph:'Paste your create table and create policy statements here…', full:true},
  firebase:{scan:firestoreScan, demo:DEMO_FIRESTORE, name:'Firebase', path:'firestore.rules', ph:'Paste your firestore.rules here…', full:false}
};

/* ---------- render ---------- */
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const cssVar=s=>s<60?'--crit':s<80?'--warn':'--safe';
const VERDICT={
  unsafe:['Leaking','Anyone on the internet can walk through the holes below. Fix these, then run the full verifier to catch what a text scan can’t reach.'],
  review:['Worth a closer look','Nothing is unmistakably open, but a few rules depend on how your app behaves at runtime. The full verifier settles them by attack.'],
  clear:['No obvious holes','The schema has no unmistakable leaks. That is not the same as proven safe — run the full verifier to attack it and be sure.'],
  empty:['Nothing to check yet','Paste your Supabase migration SQL above, or load the example.']
};

function gauge(score){
  const R=46, C=2*Math.PI*R, col=`var(${cssVar(score)})`;
  const off=C*(1-score/100);
  return `<div class="gauge">
    <svg width="104" height="104" viewBox="0 0 104 104">
      <circle cx="52" cy="52" r="${R}" fill="none" stroke="var(--line-2)" stroke-width="6"/>
      <circle cx="52" cy="52" r="${R}" fill="none" stroke="${col}" stroke-width="6" stroke-linecap="round"
        stroke-dasharray="${C.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/>
    </svg>
    <div class="center"><div class="score" style="color:${col}">${score}</div><div class="max">of 100</div></div>
  </div>`;
}
function badgeSVG(score){
  const c=score<60?'#c23934':score<80?'#9a6b0e':'#177f53';const lw=76,vw=34,h=20;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${lw+vw}" height="${h}" viewBox="0 0 ${lw+vw} ${h}" role="img" aria-label="Guard Score: ${score}">
  <clipPath id="rb"><rect width="${lw+vw}" height="${h}" rx="4"/></clipPath>
  <g clip-path="url(#rb)"><rect width="${lw}" height="${h}" fill="#3a3f4b"/><rect x="${lw}" width="${vw}" height="${h}" fill="${c}"/></g>
  <g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">
    <text x="${lw/2}" y="14">Guard Score</text><text x="${lw+vw/2}" y="14" font-weight="bold">${score}</text></g></svg>`;
}

function render(sql){
  const r=STACKS[stack].scan(sql);
  const el=document.getElementById('result');el.hidden=false;
  const [vh,vs]=VERDICT[r.verdict]||VERDICT.empty;
  const chips=[];
  if(r.counts.critical)chips.push(`<span class="chip c"><b>${r.counts.critical}</b> critical</span>`);
  if(r.counts.high)chips.push(`<span class="chip h"><b>${r.counts.high}</b> high</span>`);
  if(r.counts.warning)chips.push(`<span class="chip w"><b>${r.counts.warning}</b> to review</span>`);
  if(!r.findings.length&&r.tableCount)chips.push(`<span class="chip s">${r.tableCount} tables · no obvious holes</span>`);

  const findings=r.findings.map(f=>`
    <div class="finding">
      <div class="sev ${f.severity}">${f.severity}</div>
      <div class="f-body">
        <div class="tbl">${esc(f.table)}</div>
        <div class="what">${esc(f.what)}</div>
        <details><summary>Show the fix</summary><pre>${esc(f.fix)}</pre></details>
      </div>
    </div>`).join('');

  const md=`[![Guard Score](${location.origin}/badge/${r.guardScore}.svg)](${location.origin})`;

  const upsell = STACKS[stack].full ? `
    <div class="block">
      <h3>What the full verifier proves that a text scan can’t</h3>
      <p class="sub">It builds a private copy of your database and attacks it. Only an attack can confirm these:</p>
      <ul class="adds">
        <li><span class="mk">✓</span><div>A signed-in user <b>promoting themselves to admin</b> or upgrading their own plan, when a rule trusts a field they control.</div></li>
        <li><span class="mk">✓</span><div>One customer <b>reading another customer’s data</b> across a tenant boundary that runs through a helper function.</div></li>
        <li><span class="mk">✓</span><div>A <b>security-definer function or RPC</b> that returns other users’ rows to anyone who calls it.</div></li>
        <li><span class="mk">✓</span><div>A <b>blind write</b> to rows the attacker can’t even read — then a check that your own users still work.</div></li>
      </ul>
      <div class="runline">
        <a class="primary" href="#how">Run the full verifier</a>
        <div class="snippet" style="margin-top:0;flex:1;min-width:220px"><code id="cmd">npx verified-changes check ./your-app</code><button class="copy" data-copy="cmd">Copy</button></div>
      </div>
    </div>` : `
    <div class="block">
      <h3>The full Firebase engine is on the way</h3>
      <p class="sub">This is the static preview. The full engine builds a private copy of your Firestore database in the emulator and attacks it as a real intruder — the same method that makes the Supabase engine the most accurate tool tested. It proves what a text scan can only guess at:</p>
      <ul class="adds">
        <li><span class="mk">✓</span><div>A rule that looks safe but is <b>bypassed through get() / exists()</b> lookups an attacker can satisfy.</div></li>
        <li><span class="mk">✓</span><div>One user <b>reading or overwriting another user’s documents</b> where the ownership check is subtly wrong.</div></li>
        <li><span class="mk">✓</span><div>Data reachable through a <b>collection-group query</b> the per-collection rules never anticipated.</div></li>
        <li><span class="mk">✓</span><div>A <b>public Storage bucket</b> or an open callable function behind the app.</div></li>
      </ul>
      <div class="runline">
        <a class="primary" href="#how">See how the engines work</a>
        <span class="hint" style="color:var(--muted)">The Supabase engine is live and benchmarked today.</span>
      </div>
    </div>`;

  el.innerHTML=`
    <div class="report">
      <div class="report-head">
        ${gauge(r.guardScore)}
        <div class="verdict">
          <h2>${vh}</h2>
          <p>${vs}</p>
          <div class="chips">${chips.join('')}</div>
        </div>
      </div>
      ${r.findings.length?`<div class="findings">${findings}</div>`:''}
    </div>

    <div class="block">
      <h3>Share your Guard Score</h3>
      <p class="sub">Add the badge to your README or your deployed app — proof you checked, and a prompt for the next builder to check theirs.</p>
      <div class="share-row">${badgeSVG(r.guardScore)}</div>
      <div class="snippet"><code id="md">${esc(md)}</code><button class="copy" data-copy="md">Copy</button></div>
    </div>
    ${upsell}`;

  el.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',async()=>{
    const t=document.getElementById(b.dataset.copy).textContent;
    try{await navigator.clipboard.writeText(t);const o=b.textContent;b.textContent='Copied';setTimeout(()=>b.textContent=o,1400);}
    catch{const rng=document.createRange();rng.selectNodeContents(document.getElementById(b.dataset.copy));const sel=getSelection();sel.removeAllRanges();sel.addRange(rng);}
  }));
}

/* ---------- wiring ---------- */
const ta=document.getElementById('sql');
function applyStack(){
  const c=STACKS[stack];
  document.getElementById('cpath').textContent=c.path;
  document.getElementById('stackname').textContent=c.name;
  ta.placeholder=c.ph;
  document.querySelectorAll('.stackbtn').forEach(x=>{const on=x.dataset.stack===stack;x.classList.toggle('active',on);x.setAttribute('aria-selected',on);});
}
function loadDemo(){ta.value=STACKS[stack].demo;render(ta.value);}
document.getElementById('scan').addEventListener('click',()=>{render(ta.value);document.getElementById('result').scrollIntoView({behavior:'smooth',block:'nearest'});});
document.getElementById('demo').addEventListener('click',()=>{loadDemo();document.getElementById('result').scrollIntoView({behavior:'smooth',block:'nearest'});});
document.querySelectorAll('.stackbtn').forEach(btn=>btn.addEventListener('click',()=>{stack=btn.dataset.stack;applyStack();loadDemo();}));

const root=document.documentElement;
try{const saved=localStorage.getItem('gs-theme');if(saved)root.setAttribute('data-theme',saved);}catch{}
document.getElementById('theme').addEventListener('click',()=>{
  const cur=root.getAttribute('data-theme');
  const dark=cur?cur==='dark':matchMedia('(prefers-color-scheme: dark)').matches;
  const next=dark?'light':'dark';root.setAttribute('data-theme',next);
  try{localStorage.setItem('gs-theme',next);}catch{}
});

/* open already showing the example — complete at rest */
applyStack();loadDemo();