// EarnZone — Telegram identity verifier (NEW, fixes fake-Telegram-ID bug)
//
// Client `initData` (raw string, tg.initData) bhejta hai. Hum Telegram ke
// documented HMAC-SHA256 se verify karte hain ke woh sach mein tumhare bot
// ne sign kiya hai. Pass hone par Firebase Custom Token milta hai jiska
// uid = "tg_<telegramId>" — isliye ab koi kisi aur ka uid ban hi nahi sakta.
//
// Netlify env vars: TELEGRAM_BOT_TOKEN, FIREBASE_PROJECT_ID,
// FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, FIREBASE_DB_URL,
// ALLOWED_ORIGIN (e.g. https://tumhari-site.netlify.app), INITDATA_MAX_AGE_SEC (optional, default 86400)
// Legacy-migration (optional): MIGRATION_MAX_PTS (default 10000), MIGRATION_MAX_REFS (default 100),
//   MIGRATION_DISABLED=1 (migration band), MIGRATION_UNTIL (ISO date ya epoch-ms; uske baad migration band)

const crypto = require("crypto");
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

function safeEqualHex(a, b) {
  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}

// Telegram WebApp initData verification (official algorithm)
function verifyInitData(initData, botToken, maxAgeSec) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash || !/^[0-9a-f]{64}$/i.test(hash)) return null;
  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([k, v]) => k + "=" + v)
    .join("\n");

  const secretKey = crypto.createHmac("sha256", "WebAppData").update(botToken).digest();
  const calc = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
  if (!safeEqualHex(calc, hash.toLowerCase())) return null;

  const authDate = Number(params.get("auth_date"));
  if (!authDate || Date.now() / 1000 - authDate > maxAgeSec) return null;
  if (authDate - Date.now() / 1000 > 300) return null; // future timestamp

  let user;
  try { user = JSON.parse(params.get("user") || ""); } catch (_) { return null; }
  if (!user || !Number.isSafeInteger(user.id) || user.id <= 0 || user.is_bot) return null;
  return user;
}


// 🔧 FIX #4 (v2 — hardened): Purane users ka data migrate karo.
// Purane build mein app-uid random "user_xxx_123" tha aur data CLIENT-written tha (unverified).
// Isliye migration ab data ko blind copy NAHI karta:
//   - sirf whitelist wale fields copy hote hain, har ek type/range clamp hoti hai
//   - pts/today/refs ki upper limit (env se) — excess sirf legacyUsers backup + migrationReview mein rehta hai
//   - server-controlled fields (adVerifiedAt, adConsumedAt, lastEarnAt) copy nahi hote
//   - promoRedemptions bhi naye uid par jaate hain (warna purane promo dobara redeem ho jaate)
//   - MIGRATION_DISABLED / MIGRATION_UNTIL se migration window band ki ja sakti hai
// Failure login ko block nahi karta.

const envInt = (name, dflt) => { const n = Number(process.env[name]); return Number.isFinite(n) && n >= 0 ? Math.floor(n) : dflt; };
const clampInt = (v, min, max) => { const n = Number(v); return Number.isFinite(n) ? Math.min(Math.max(Math.round(n), min), max) : min; };
const cleanStr = (v, max) => (typeof v === "string" ? v.replace(/[\u0000-\u001f]/g, " ").slice(0, max) : "");

function migrationOpen() {
  if (/^(1|true|yes)$/i.test(String(process.env.MIGRATION_DISABLED || ""))) return false;
  const until = process.env.MIGRATION_UNTIL;
  if (until) {
    const t = /^\d+$/.test(until) ? Number(until) : Date.parse(until);
    if (Number.isFinite(t) && Date.now() > t) return false;
  }
  return true;
}

// Purane (untrusted) node -> naya safe node. flags = jo kuch cap/clamp hua uski list (admin review ke liye)
function sanitizeLegacy(old, newUid, oldUid, now, lim) {
  const flags = [];
  const o = old && typeof old === "object" ? old : {};
  const c = {};

  const origPts = clampInt(o.pts, 0, 2000000);
  c.pts = Math.min(origPts, lim.maxPts);
  if (origPts > c.pts) flags.push("pts:" + origPts + "->" + c.pts);

  const origToday = clampInt(o.today, 0, 2000000);
  c.today = Math.min(origToday, lim.maxPts);
  if (origToday > c.today) flags.push("today:" + origToday + "->" + c.today);

  const origRefs = clampInt(o.refs, 0, 1000000);
  c.refs = Math.min(origRefs, lim.maxRefs);
  if (origRefs > c.refs) flags.push("refs:" + origRefs + "->" + c.refs);

  c.tasksDone = clampInt(o.tasksDone, 0, 1000);
  c.streak = clampInt(o.streak, 0, 365);
  c.name = cleanStr(o.name, 40);
  c.lang = cleanStr(o.lang, 10);
  c.lastDate = cleanStr(o.lastDate, 60);
  c.lastStreakDate = cleanStr(o.lastStreakDate, 60);
  c.checkedIn = o.checkedIn === true;
  c.lastCheckinAt = clampInt(o.lastCheckinAt, 0, now);
  c.usedRef = o.usedRef === true;
  if (typeof o.referredBy === "string" && /^tg_[0-9]{1,15}$/.test(o.referredBy)) c.referredBy = o.referredBy;
  if (typeof o.code === "string" && /^EARN[A-Z0-9]{4,6}$/.test(o.code)) c.code = o.code;
  c.lastPromoCode = typeof o.lastPromoCode === "string" && /^[A-Z0-9]{3,20}$/.test(o.lastPromoCode) ? o.lastPromoCode : "";

  ["spinEnd", "scratchEnd", "quizEnd", "capEnd", "slotEnd"].forEach((k) => { c[k] = clampInt(o[k], 0, now + 7 * 86400000); });

  const numMap = (src, keys) => { const r = {}; keys.forEach((k) => { r[k] = clampInt(src && src[k], 0, 1000000); }); return r; };
  c.stats = numMap(o.stats, ["spins", "scratches", "quizzes", "captchas", "slots"]);
  c.dailyPlays = numMap(o.dailyPlays, ["spin", "scratch", "quiz", "captcha", "slot"]);

  const toList = (v) => (Array.isArray(v) ? v : v && typeof v === "object" ? Object.values(v) : []);
  c.unlockedBadges = toList(o.unlockedBadges).filter((x) => typeof x === "string").map((x) => cleanStr(x, 40)).slice(0, 60);
  c.doneTasks = [...new Set(toList(o.doneTasks).filter((x) => typeof x === "string" && /^[A-Za-z0-9_-]{1,40}$/.test(x)))].slice(0, 200);
  c.history = toList(o.history).filter((h) => h && typeof h === "object").slice(0, 20)
    .map((h) => ({ src: cleanStr(h.src, 60), n: clampInt(h.n, 0, lim.maxPts), t: cleanStr(h.t, 30) }));

  // txns: pending/paid/rejected redeem requests — sirf known fields, pts capped
  const STAT = new Set(["pending", "paid", "rejected"]);
  c.txns = toList(o.txns).filter((t) => t && typeof t === "object" && STAT.has(t.status)).slice(0, 200).map((t) => {
    const r = {
      itemId: cleanStr(t.itemId, 40), itemName: cleanStr(t.itemName, 60), itemIcon: cleanStr(t.itemIcon, 10),
      tierId: cleanStr(t.tierId, 40), tierLabel: cleanStr(t.tierLabel, 60),
      method: cleanStr(t.method, 60), account: cleanStr(t.account, 80), date: cleanStr(t.date, 40),
      pts: clampInt(t.pts, 0, 100000), status: t.status, submittedAt: clampInt(t.submittedAt, 0, now),
    };
    if (t.processedAt != null) r.processedAt = clampInt(t.processedAt, 0, now);
    return r;
  });
  if (toList(o.txns).length > c.txns.length) flags.push("txns:dropped-" + (toList(o.txns).length - c.txns.length));

  c.lastDevice = newUid;
  c.lastSeen = now;
  c.migratedFrom = oldUid;
  c.migratedAt = now;
  return { clean: c, flags };
}

async function movePromoRedemptions(db, oldUid, newUid, updates) {
  const codes = Object.keys((await db.ref("promoCodes").once("value")).val() || {}).slice(0, 300);
  const snaps = await Promise.all(codes.map((code) => db.ref("promoRedemptions/" + code + "/" + oldUid).once("value")));
  codes.forEach((code, i) => {
    if (snaps[i].val() === true) {
      updates["promoRedemptions/" + code + "/" + newUid] = true;
      updates["promoRedemptions/" + code + "/" + oldUid] = null;
    }
  });
}

async function migrateLegacyUser(newUid) {
  if (!migrationOpen()) return;
  const db = admin.database();
  const newRef = db.ref("users/" + newUid);
  if ((await newRef.child("pts").once("value")).exists()) return;          // naya node pehle se hai — kuch mat karo

  // Purana uid device record se milta hai (fingerprint = "tg_<id>" = newUid)
  const devSnap = await db.ref("devices/" + newUid).once("value");
  if (!devSnap.exists()) return;                                            // bilkul naya user
  const dv = devSnap.val();
  const oldUid = dv && typeof dv === "object" ? dv.uid : dv;
  if (oldUid === newUid) return;                                            // already migrated
  // Sirf purane format ka uid — koi tg_ uid kabhi migrate source nahi banega
  if (typeof oldUid !== "string" || !/^user_[a-z0-9]+_[0-9]+$/i.test(oldUid)) return;

  const oldSnap = await db.ref("users/" + oldUid).once("value");
  if (!oldSnap.exists()) {
    // Data nahi hai, par device lock na lage isliye pointer naye uid par le aao
    await db.ref("devices/" + newUid + "/uid").set(newUid);
    return;
  }
  const old = oldSnap.val();
  // Ownership ka saboot: purane node ne is Telegram device ko khud record kiya hona chahiye
  if (old.lastDevice && old.lastDevice !== newUid) return;

  const now = Date.now();
  const lim = { maxPts: envInt("MIGRATION_MAX_PTS", 10000), maxRefs: envInt("MIGRATION_MAX_REFS", 100) };
  const { clean, flags } = sanitizeLegacy(old, newUid, oldUid, now, lim);

  const tx = await newRef.transaction((cur) => (cur === null ? clean : undefined));
  if (!tx.committed) return;                                                // race: kisi aur request ne kar diya

  const updates = {};
  updates["devices/" + newUid + "/uid"] = newUid;
  updates["legacyUsers/" + oldUid] = old;                                   // ORIGINAL (uncapped) backup
  updates["users/" + oldUid] = null;                                        // duplicate hatao
  if (clean.code) updates["codes/" + clean.code] = newUid;
  const lb = (await db.ref("leaderboard/" + oldUid).once("value")).val();
  if (lb && typeof lb === "object") {
    updates["leaderboard/" + newUid] = { name: cleanStr(lb.name, 40) || clean.name || "EarnZone User", refs: clean.refs };
    updates["leaderboard/" + oldUid] = null;
  }
  const ban = (await db.ref("deviceLock/" + oldUid).once("value")).val();   // ban bhi saath jaaye
  if (ban) { updates["deviceLock/" + newUid] = ban; updates["deviceLock/" + oldUid] = null; }
  try { await movePromoRedemptions(db, oldUid, newUid, updates); } catch (e) { console.error("promo move error:", e && e.message); }
  if (flags.length) updates["migrationReview/" + newUid] = { oldUid, flags, at: now };   // admin review (Firebase Console)
  await db.ref().update(updates);
  console.log("tg-auth: migrated", oldUid, "->", newUid, flags.length ? "FLAGGED " + flags.join(",") : "");
}

// 🔒 FIX (#10): referral abuse detection ke liye user ka network (IP) HASH karke rakho — raw IP kabhi store nahi hoti.
// userMeta/{uid} = { ip, ips{hash:ts (last 10)}, firstSeen, lastSeen }, ipIndex/{hash}/{uid} = ts. Dono sirf server (admin SDK) padh/likh sakta hai.
function clientIp(event) {
  const h = (event && event.headers) || {};
  const v = h["x-nf-client-connection-ip"] || h["client-ip"] || String(h["x-forwarded-for"] || "").split(",")[0];
  return String(v || "").trim().slice(0, 64);
}
async function recordNetwork(uid, ip) {
  if (!ip) return;
  const salt = process.env.IP_HASH_SALT || process.env.TELEGRAM_BOT_TOKEN || "";
  const hash = require("crypto").createHash("sha256").update(salt + "|" + ip).digest("hex").slice(0, 24);
  const db = admin.database();
  const now = Date.now();
  const cur = (await db.ref("userMeta/" + uid).once("value")).val() || {};
  const ips = cur.ips && typeof cur.ips === "object" ? cur.ips : {};
  ips[hash] = now;
  Object.keys(ips).sort((a, b) => ips[b] - ips[a]).slice(10).forEach((k) => { delete ips[k]; });   // sirf 10 sabse recent
  await db.ref().update({
    ["userMeta/" + uid]: { ip: hash, ips, firstSeen: cur.firstSeen || now, lastSeen: now },
    ["ipIndex/" + hash + "/" + uid]: now,
  });
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
  const headers = cors(event.headers && (event.headers.origin || event.headers.Origin), "Content-Type, X-Firebase-AppCheck");
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "method" }) };
  if (!(await appCheckOk(event))) return { statusCode: 401, headers, body: JSON.stringify({ error: "app-check" }) };

  try {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    if (!botToken) return { statusCode: 500, headers, body: JSON.stringify({ error: "server-config" }) };

    let body;
    try { body = JSON.parse(event.body || "{}"); } catch (_) { body = {}; }
    const initData = typeof body.initData === "string" ? body.initData : "";
    if (!initData || initData.length > 4096) return { statusCode: 400, headers, body: JSON.stringify({ error: "bad-request" }) };

    const maxAge = Number(process.env.INITDATA_MAX_AGE_SEC) || 86400;
    const user = verifyInitData(initData, botToken, maxAge);
    if (!user) return { statusCode: 401, headers, body: JSON.stringify({ error: "invalid-init-data" }) };

    const uid = "tg_" + user.id;
    try { await migrateLegacyUser(uid); } catch (e) { console.error("migrate error:", e && e.message); }
    try { await recordNetwork(uid, clientIp(event)); } catch (e) { console.error("network record error:", e && e.message); }   // login block nahi karta
    const token = await admin.auth().createCustomToken(uid);
    return { statusCode: 200, headers, body: JSON.stringify({ token, uid }) };
  } catch (err) {
    console.error("tg-auth error:", err && err.message);
    return { statusCode: 500, headers, body: JSON.stringify({ error: "server" }) };
  }
};
                                                                
