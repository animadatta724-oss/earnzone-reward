// EarnZone — Telegram payout-proof poster (server-side)  [FIX #5]
//
// Pehle: admin panel Telegram Bot Token browser ke localStorage mein rakhta tha aur seedha
// api.telegram.org ko call karta tha -> token XSS / extension / shared-PC se leak ho sakta tha.
// Ab: token sirf Netlify env mein rehta hai. Admin panel apna Firebase ID token bhejta hai;
// function verify karti hai ki caller admin email hai, tabhi post karti hai.
//
// Netlify env vars:
//   TG_PAYOUT_BOT_TOKEN    (payout-proof channel ka bot — tg-auth wale TELEGRAM_BOT_TOKEN se ALAG bot rakho)
//   TG_PAYOUT_CHANNEL_ID   (e.g. @your_channel ya -1001234567890)
//   ADMIN_EMAIL            (optional, comma-separated, default suman@earnzone.com)
//   + Firebase `adminEmails/{email with . -> ,}` = true wale saare admins bhi allowed (admin panel super-admin login par sync karta hai)
//   ADMIN_ORIGIN           (admin panel ka origin, comma-separated ho sakta hai, e.g. https://admin.tumhari-site.com)
//   FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, FIREBASE_DB_URL
//
// Request: POST  Authorization: Bearer <admin Firebase ID token>
//   {action:"test"}
//   {action:"post", name, item, tier, pts}     (name pehle se masked aata hai; text server banata hai)

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

function cors(origin) {
  const list = (process.env.ADMIN_ORIGIN || "").split(",").map((x) => x.trim()).filter(Boolean);
  const h = { "Content-Type": "application/json", "Cache-Control": "no-store", "Vary": "Origin" };
  if (origin && list.includes(origin)) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    h["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Firebase-AppCheck";
  }
  return h;
}

const reply = (code, headers, obj) => ({ statusCode: code, headers, body: JSON.stringify(obj) });
const clean = (v, max) => String(v == null ? "" : v).replace(/[\u0000-\u001f]/g, " ").slice(0, max);

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
    const botToken = process.env.TG_PAYOUT_BOT_TOKEN;
    const channelId = process.env.TG_PAYOUT_CHANNEL_ID;
    if (!botToken || !channelId) return reply(500, headers, { error: "server-config" });

    // Admin check (Firebase rules bhi isi email par chalti hain)
    const m = ((event.headers && (event.headers.authorization || event.headers.Authorization)) || "").match(/^Bearer (.+)$/);
    if (!m) return reply(401, headers, { error: "no-token" });
    let decoded;
    try { decoded = await admin.auth().verifyIdToken(m[1]); }
    catch (_) { return reply(401, headers, { error: "bad-token" }); }
    // FIX (#8): pehle sirf ek hardcoded email chalta tha, isliye panel ke doosre admins ko 403 milta tha.
    // Ab: env list YA database ke adminEmails node (rules ke saath same source) — dono mein se koi bhi.
    const email = String(decoded.email || "").trim().toLowerCase();
    if (!email) return reply(403, headers, { error: "not-admin" });
    const envAdmins = (process.env.ADMIN_EMAIL || "suman@earnzone.com").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
    let isAdmin = envAdmins.includes(email);   // env wale (bootstrap) admins: pehle se bane hue accounts
    if (!isAdmin && /^[^\s#$\[\]\/]+$/.test(email)) {
      try { isAdmin = (await admin.database().ref("adminEmails/" + email.replace(/\./g, ",")).once("value")).val() === true; }
      catch (e) { console.error("admin lookup error:", e && e.message); }
      // FIX (low): DB-list wale admin ki email VERIFIED honi chahiye — warna koi us email se pehle sign-up karke
      // (unverified) admin ban sakta tha. (Rules mein bhi yahi check hai: auth.token.email_verified.)
      if (isAdmin && decoded.email_verified !== true) return reply(403, headers, { error: "email-not-verified" });
    }
    if (!isAdmin) return reply(403, headers, { error: "not-admin" });

    let body; try { body = JSON.parse(event.body || "{}"); } catch (_) { body = {}; }

    let text;
    if (body.action === "test") {
      text = "✅ Test Post — EarnZone Payout Proof channel connected successfully!\n\n#PayoutProof";
    } else if (body.action === "post") {
      const pts = Math.max(0, parseInt(body.pts) || 0);
      text =
        "✅ Payout Confirmed!\n\n" +
        "👤 User: " + clean(body.name, 40) + "\n" +
        "🎁 Reward: " + clean(body.item, 80) + (body.tier ? " — " + clean(body.tier, 60) : "") + "\n" +
        "🪙 Coins Used: " + pts.toLocaleString("en-US") + "\n" +
        "📅 Date: " + new Date().toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" }) + "\n\n" +
        "#PayoutProof";
    } else {
      return reply(400, headers, { error: "bad-action" });
    }

    const r = await fetch("https://api.telegram.org/bot" + botToken + "/sendMessage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: channelId, text }),
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) return reply(502, headers, { error: "telegram", description: clean(j.description, 200) });
    return reply(200, headers, { ok: true });
  } catch (err) {
    console.error("tg-payout error:", err && err.message);
    return reply(500, headers, { error: "server" });
  }
};
