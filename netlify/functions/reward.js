// EarnZone — Monetag Postback receiver (v4 — hardened)
// v5: rate-limit atomic (transaction) + gap 60s -> 10s (REWARD_MIN_GAP_MS)
// Changes vs v3:
//  - reward sirf "yes" par credit (missing/empty/other => ignore)
//  - ymid strict format: tg_<digits> (fake/junk user nodes nahi banenge)
//  - secret constant-time compare
//  - sirf EXISTING user ko flag milta hai (update() naya node bana deta tha)
//
// Postback URL (Monetag):
// https://tumhari-site.netlify.app/.netlify/functions/reward?ymid={ymid}&event={event_type}&reward={reward_event_type}&secret=TUMHARA_SECRET

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
const db = admin.database();

function secretOk(given) {
  const expected = process.env.REWARD_SECRET || "";
  if (!expected || typeof given !== "string") return false;
  const a = crypto.createHash("sha256").update(given).digest();
  const b = crypto.createHash("sha256").update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}

exports.handler = async (event) => {
  try {
    const params = event.queryStringParameters || {};
    const { ymid, secret, reward } = params;

    if (!secretOk(secret)) return { statusCode: 403, body: "Forbidden" };

    if (typeof ymid !== "string" || !/^tg_[0-9]{1,15}$/.test(ymid)) {
      return { statusCode: 400, body: "Bad ymid" };
    }

    if (String(reward || "").toLowerCase() !== "yes") {
      console.warn("reward ignored, value:", JSON.stringify(reward));
      return { statusCode: 200, body: "Ignored" };
    }

    const userRef = db.ref("users/" + ymid);
    // Sirf existing user (pts field hamesha game save ke saath banta hai)
    const exists = (await userRef.child("pts").once("value")).exists();
    if (!exists) return { statusCode: 200, body: "Ignored — unknown user" };

    // 🔒 SECURITY: replay/abuse guard (secret leak hone par direct URL spam rokta hai).
    // FIX (#5): pehle gap 60s tha aur check + write alag the:
    //   - genuine user 60s ke andar doosra ad dekhta to postback "Ignored" hota aur game
    //     30s baad "Ad verify nahi ho paya" dikhata tha (reward gayab)
    //   - check-then-write atomic nahi tha, do parallel postbacks dono nikal jaate the
    // Ab: gap chhota (default 10s, env REWARD_MIN_GAP_MS) aur check+write EK transaction mein.
    // Ek asli ad dekhne mein hi 10s+ lagte hain, isliye genuine postback kabhi block nahi hoga;
    // Monetag ka duplicate/retry postback (kuch second ke andar) block hoga.
    const minGap = Math.min(Math.max(Number(process.env.REWARD_MIN_GAP_MS) || 10000, 1000), 60000);
    const now = Date.now();
    const tx = await userRef.child("adVerifiedAt").transaction((cur) =>
      (typeof cur === "number" && now - cur < minGap) ? undefined : now   // undefined = abort (too soon)
    );
    if (!tx.committed) {
      console.warn("reward ignored — too soon after last verify, ymid:", ymid);
      return { statusCode: 200, body: "Ignored — rate limited" };
    }
    return { statusCode: 200, body: "OK" };
  } catch (err) {
    console.error("reward function error:", err && err.message);
    return { statusCode: 500, body: "Server error" };
  }
};
