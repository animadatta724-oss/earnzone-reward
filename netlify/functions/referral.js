// EarnZone — Referral reward (server-side)  [FIX #1: yeh function deploy mein missing tha]
//
// Game (applyReferral) is endpoint ko call karta hai:
//   POST /.netlify/functions/referral   Authorization: Bearer <Firebase ID token>   body: {code}
//
// Kya karta hai:
//   1. ID token verify  -> caller uid (tg_<id>)
//   2. codes/{code} se owner uid nikalta hai (client par bharosa nahi)
//   3. Caller ke users/{uid} mein usedRef===true aur referredBy===owner hona chahiye
//      (nahi to 409 -> game retry karta hai, kyunki client ka write abhi pahuncha nahi)
//   4. refClaims/{uid} transaction se EK hi baar reward (double-claim / replay block)
//   5. v3 (#10): abuse checks (same network / ek IP par bahut accounts / owner daily cap). Fail -> refClaims/{uid}.blocked, koi reward nahi
//   6. Owner (refs+1, pts+bonus) aur REFEREE (pts+bonus) dono ko reward SERVER deta hai — har side idempotent flag
//      (refClaims/{uid}/ownerPaid, refereePaid) se: retry par double reward nahi, aur ek side fail hone par dusri safe
//      (Referee ka bonus pehle client-side tha aur rules mein khula tha — ab rules se hata diya gaya hai)
//
// Netlify env vars: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY,
//                   FIREBASE_DB_URL, ALLOWED_ORIGIN
// Optional: REF_IP_CHECK (default on; "off" = IP checks band), REF_MAX_ACCOUNTS_PER_IP (default 5), REF_OWNER_DAILY_CAP (default 25)

const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
    }),
    databaseURL: process.env.FIREBASE_DB_URL,
  });
}
const db = admin.database();

const MAX_TOTAL_PTS = 500000;   // task-claim.js / game ke MAX_TOTAL_PTS jaisa

// tg-auth.js jaisa hi CORS (blogspot country-TLD variants allow)
// 🔒 FIX (Blocker #3): CORS ab strict hai.
// Pehle regex `blogspot\.[a-z.]+` tha — isse `sub.blogspot.evil.com` jaisa attacker domain bhi pass ho jata tha.
// Ab: ALLOWED_ORIGIN (comma-separated ho sakta hai) ka EXACT match, ya Blogspot ke sirf
// Google ke asli country-domains (neeche list) — koi bhi random TLD nahi.
const BLOGSPOT_TLDS = new Set([
  "com","ae","al","am","ba","be","bg","bj","ca","cf","ch","cl","cv","cz","de","dk","fi","fr","gr","hk","hr","hu",
  "ie","in","is","it","jp","kr","li","lt","lu","md","mk","mr","mx","my","nl","no","pe","pt","qa","re","ro","rs",
  "ru","se","sg","si","sk","sn","td","tw","ug","vn",
  "co.at","co.id","co.il","co.ke","co.nz","co.uk","co.za",
  "com.ar","com.au","com.br","com.by","com.co","com.cy","com.ee","com.eg","com.es","com.mt","com.ng","com.tr","com.uy",
]);

function originAllowed(origin, allowedRaw) {
  if (!origin || !allowedRaw) return false;
  const list = String(allowedRaw).split(",").map((x) => x.trim()).filter(Boolean);
  let oHost;
  try {
    const o = new URL(origin);
    if (o.protocol !== "https:") return list.includes(origin);   // http sirf exact-match se (dev)
    oHost = o.hostname.toLowerCase();
  } catch (_) { return false; }
  for (const a of list) {
    if (origin === a) return true;
    try {
      const aHost = new URL(a).hostname.toLowerCase();
      const m = aHost.match(/^([a-z0-9-]+)\.blogspot\.([a-z.]+)$/);
      if (!m || !BLOGSPOT_TLDS.has(m[2])) continue;
      const om = oHost.match(/^([a-z0-9-]+)\.blogspot\.([a-z.]+)$/);
      if (om && om[1] === m[1] && BLOGSPOT_TLDS.has(om[2])) return true;
    } catch (_) { /* malformed allowed entry — skip */ }
  }
  return false;
}

function cors(origin, allowHeaders) {
  const h = { "Content-Type": "application/json", "Cache-Control": "no-store", "Vary": "Origin" };
  if (originAllowed(origin, process.env.ALLOWED_ORIGIN)) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    h["Access-Control-Allow-Headers"] = allowHeaders || "Content-Type, Authorization, X-Firebase-AppCheck";
  }
  return h;
}

const reply = (code, headers, obj) => ({ statusCode: code, headers, body: JSON.stringify(obj) });

const IP_CHECK = !/^(0|off|false|no)$/i.test(String(process.env.REF_IP_CHECK || "on"));
const MAX_PER_IP = Math.max(1, Number(process.env.REF_MAX_ACCOUNTS_PER_IP) || 5);
const OWNER_DAILY_CAP = Math.max(1, Number(process.env.REF_OWNER_DAILY_CAP) || 25);
const dayKey = () => new Date(Date.now() + 5.5 * 3600000).toISOString().slice(0, 10);   // IST din

// Multi-account self-referral rokne ke checks. Meta (tg-auth login se) na ho to IP checks skip (fail-open).
async function abuseReason(uid, ownerUid) {
  if (IP_CHECK) {
    const [me, ow] = await Promise.all([db.ref("userMeta/" + uid).once("value"), db.ref("userMeta/" + ownerUid).once("value")]);
    const mv = me.val(), ov = ow.val();
    if (mv && mv.ip) {
      const mine = Object.keys(mv.ips || { [mv.ip]: 1 });
      const theirs = Object.keys((ov && ov.ips) || {});
      if (mine.some((h) => theirs.includes(h))) return "same-network";               // referrer aur referee ek hi network par
      const crowd = (await db.ref("ipIndex/" + mv.ip).once("value")).numChildren();
      if (crowd > MAX_PER_IP) return "ip-limit";                                     // ek IP par bahut saare accounts
    }
  }
  const n = Number((await db.ref("refStats/" + ownerUid + "/" + dayKey()).once("value")).val()) || 0;
  if (n >= OWNER_DAILY_CAP) return "owner-daily-cap";
  return null;
}

// Ek flag ek hi baar: flag set (transaction) -> pay -> pay fail ho to flag wapas (retry safe)
async function payOnce(uid, flag, fn) {
  const fref = db.ref("refClaims/" + uid + "/" + flag);
  const t = await fref.transaction((c) => (c === true ? undefined : true));
  if (!t.committed) return null;                // pehle hi ho chuka
  try { return await fn(); }
  catch (e) { await fref.remove().catch(() => {}); throw e; }
}

// users/{u} par atomic credit. extra(u, given) refs/history jaisi cheezein set karta hai.
async function credit(u_uid, bonus, extra) {
  let outcome = "", given = 0;
  const tx = await db.ref("users/" + u_uid).transaction((u) => {
    outcome = "";
    if (u === null || typeof u !== "object") return u;            // local cache khaali — SDK server value ke saath retry karega
    if (typeof u.pts !== "number") { outcome = "nouser"; return; }
    given = Math.max(0, Math.min(bonus, MAX_TOTAL_PTS - u.pts));
    u.pts = u.pts + given;
    if (typeof u.today === "number") u.today = u.today + given;
    extra(u, given);
    outcome = "ok";
    return u;
  });
  if (!tx.committed || outcome !== "ok") throw new Error(outcome || "tx-not-committed");
  return { given, node: tx.snapshot.val() };
}

// 🔒 FIX (#11): Firebase App Check server-side verify. Client "X-Firebase-AppCheck" header bhejta hai.
// APPCHECK_ENFORCE=1 hone par bina valid token ke request reject (401). Default = LOG-ONLY: sirf Netlify logs mein
// "appcheck:" warning aati hai, kuch block nahi hota — pehle logs check karo ki asli users ke token aa rahe hain, phir enforce on karo.
const APPCHECK_ENFORCE = /^(1|true|on|yes)$/i.test(String(process.env.APPCHECK_ENFORCE || ""));
async function appCheckOk(event) {
  const hd = (event && event.headers) || {};
  const tok = hd["x-firebase-appcheck"] || hd["X-Firebase-AppCheck"];
  if (!tok) { console.warn("appcheck: token missing" + (APPCHECK_ENFORCE ? " (BLOCKED)" : " (log-only)")); return !APPCHECK_ENFORCE; }
  try { await admin.appCheck().verifyToken(String(tok)); return true; }
  catch (e) { console.warn("appcheck: invalid token" + (APPCHECK_ENFORCE ? " (BLOCKED)" : " (log-only)"), e && (e.code || e.message)); return !APPCHECK_ENFORCE; }
}

exports.handler = async (event) => {
  const headers = cors(event.headers && (event.headers.origin || event.headers.Origin));
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers, body: "" };
  if (event.httpMethod !== "POST") return reply(405, headers, { error: "method" });
  if (!(await appCheckOk(event))) return { statusCode: 401, headers, body: JSON.stringify({ error: "app-check" }) };

  try {
    // 1) Auth
    const authHdr = (event.headers && (event.headers.authorization || event.headers.Authorization)) || "";
    const m = authHdr.match(/^Bearer (.+)$/);
    if (!m) return reply(401, headers, { error: "no-token" });
    let decoded;
    try { decoded = await admin.auth().verifyIdToken(m[1]); }
    catch (_) { return reply(401, headers, { error: "bad-token" }); }
    const uid = decoded.uid;
    if (!/^tg_[0-9]{1,15}$/.test(uid)) return reply(403, headers, { error: "bad-uid" });

    // 2) Input
    let body; try { body = JSON.parse(event.body || "{}"); } catch (_) { body = {}; }
    const code = typeof body.code === "string" ? body.code.toUpperCase().trim() : "";
    if (!/^EARN[A-Z0-9]{4,6}$/.test(code)) return reply(400, headers, { error: "bad-code" });

    // 3) Owner nikalo (server-side lookup)
    const ownerUid = (await db.ref("codes/" + code).once("value")).val();
    if (typeof ownerUid !== "string" || !/^tg_[0-9]{1,15}$/.test(ownerUid)) return reply(404, headers, { error: "code-not-found" });
    if (ownerUid === uid) return reply(400, headers, { error: "self-referral" });

    // 4) Caller ne sach mein referral use kiya hai? (client ka write pahunchne tak 409)
    const me = (await db.ref("users/" + uid).once("value")).val() || {};
    if (me.usedRef !== true || me.referredBy !== ownerUid) return reply(409, headers, { error: "not-ready" });
    if (!(await db.ref("users/" + ownerUid + "/pts").once("value")).exists()) return reply(404, headers, { error: "owner-missing" });

    // 5) Claim (atomic, ek uid = ek claim). v:3 = yeh naya flag-based flow.
    const cref = db.ref("refClaims/" + uid);
    await cref.transaction((cur) => (cur === null ? { owner: ownerUid, code, ts: Date.now(), v: 3 } : undefined));
    const claim = (await cref.once("value")).val() || {};
    if (!claim.v) return reply(200, headers, { ok: true, already: true });          // purana (pre-v3) claim: owner ko reward mil chuka, referee ka client-side tha
    if (claim.owner !== ownerUid) return reply(409, headers, { error: "owner-mismatch" });
    if (claim.blocked) return reply(200, headers, { ok: true, blocked: claim.blocked });

    // 6) Abuse check — sirf tab jab abhi tak kisi ko reward nahi gaya
    if (!claim.ownerPaid && !claim.refereePaid) {
      const why = await abuseReason(uid, ownerUid);
      if (why) {
        await cref.child("blocked").set(why);
        console.warn("referral blocked:", why, uid, "->", ownerUid);
        return reply(200, headers, { ok: true, blocked: why });
      }
    }

    // 7) Bonus amount admin config se (default 100, cap 1000)
    let bonus = Number((await db.ref("appConfig/earn/refBonus").once("value")).val());
    if (!isFinite(bonus) || bonus < 0) bonus = 100;
    bonus = Math.min(Math.round(bonus), 1000);

    // 8) Owner reward: refs + pts + history — ek atomic transaction, ek hi baar
    await payOnce(uid, "ownerPaid", async () => {
      const r = await credit(ownerUid, bonus, (u, given) => {
        u.refs = (typeof u.refs === "number" && u.refs >= 0 ? u.refs : 0) + 1;
        if (given > 0) {
          const h = Array.isArray(u.history) ? u.history.slice() : [];
          h.unshift({ src: "👥 Referral Reward", n: given, t: new Date().toLocaleTimeString("en-IN", { timeZone: "Asia/Kolkata" }) });
          u.history = h.slice(0, 20);
        }
      });
      try {
        const lbRef = db.ref("leaderboard/" + ownerUid);
        if ((await lbRef.child("name").once("value")).exists()) await lbRef.child("refs").set(r.node.refs);
      } catch (_) { /* non-fatal */ }
      try { await db.ref("refStats/" + ownerUid + "/" + dayKey()).transaction((c) => (Number(c) || 0) + 1); } catch (_) { /* non-fatal */ }
    });

    // 9) Referee reward: pts (+today) — history client khud dalta hai (double entry na ho)
    let refereeBonus = 0;
    await payOnce(uid, "refereePaid", async () => { refereeBonus = (await credit(uid, bonus, () => {})).given; });

    const fin = (await db.ref("users/" + uid).once("value")).val() || {};
    return reply(200, headers, { ok: true, bonus: refereeBonus, pts: fin.pts, today: fin.today });
  } catch (err) {
    console.error("referral error:", err && err.message);
    return reply(500, headers, { error: "server" });   // flags idempotent hain — client ka retry safe hai
  }
};
