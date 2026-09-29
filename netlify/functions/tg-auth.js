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

function cors(origin) {
  const allowed = process.env.ALLOWED_ORIGIN || "";
  const h = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Vary": "Origin",
  };
  // 🔒 FIX: Blogger/Blogspot country-domain redirect ka masla —
  // "earnzonegamefile.blogspot.com" waale visitors ko unke desh ke hisaab
  // se kabhi kabhi "earnzonegamefile.blogspot.in", ".ru", ".co.uk" waghera
  // pe le jaaya jaata hai. Browser ka Origin header ussi waqt badal jaata
  // hai, isliye sirf EXACT match karne se un users ke liye CORS fail ho
  // jaata tha (asal ban nahi, sirf origin mismatch). Ab hum ALLOWED_ORIGIN
  // ke sirf hostname ka pehla hissa (subdomain) nikaal kar us blogspot
  // subdomain ke KISI BHI country-TLD variant ko allow karte hain.
  let isAllowed = false;
  if (allowed && origin) {
    if (origin === allowed) {
      isAllowed = true;
    } else {
      try {
        const allowedHost = new URL(allowed).hostname; // e.g. earnzonegamefile.blogspot.com
        const originUrl = new URL(origin);
        const m = allowedHost.match(/^([a-z0-9-]+)\.blogspot\.[a-z.]+$/i);
        if (m && originUrl.protocol === "https:") {
          const subdomain = m[1];
          const originHostRe = new RegExp("^" + subdomain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\.blogspot\\.[a-z.]+$", "i");
          if (originHostRe.test(originUrl.hostname)) isAllowed = true;
        }
      } catch (_) { /* malformed origin/allowed — ignore, isAllowed stays false */ }
    }
  }
  if (isAllowed) {
    h["Access-Control-Allow-Origin"] = origin;
    h["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    h["Access-Control-Allow-Headers"] = "Content-Type";
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

exports.handler = async (event) => {
  const headers = cors(event.headers && (event.headers.origin || event.headers.Origin));
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "method" }) };

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
    const token = await admin.auth().createCustomToken(uid);
    return { statusCode: 200, headers, body: JSON.stringify({ token, uid }) };
  } catch (err) {
    console.error("tg-auth error:", err && err.message);
    return { statusCode: 500, headers, body: JSON.stringify({ error: "server" }) };
  }
};
