// EarnZone — Adsgram Reward URL receiver
// Yeh function Adsgram ke server se GET request receive karta hai jab
// user ne rewarded ad poora dekh liya ho. Yahan se Firebase Admin SDK
// se seedha 'users/{appUid}' mein pts/today/lastEarnAt update hote hain —
// client ko yeh path likhne ka access nahi (Firebase Rules se protected),
// isliye yeh server-side hi authoritative reward source hai.

const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      // Netlify env var mein private key ke andar literal "\n" hote hain,
      // unhe real newline mein convert karna padta hai.
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
    }),
    databaseURL: process.env.FIREBASE_DB_URL,
  });
}

const db = admin.database();

// Har ad-placement/type ke liye reward amount.
// Apne app ke actual point-values yahan match karo (jo abhi client-side
// har feature (spin/scratch/quiz/cap/slot) credit karta hai).
const REWARD_AMOUNTS = {
  default: 50,
  spin: 50,
  scratch: 50,
  quiz: 30,
  cap: 40,
  slot: 50,
};

const DAILY_CAP = 200000;   // rules ke "today" max se match
const TOTAL_CAP = 2000000;  // rules ke "pts" max se match
const MIN_GAP_MS = 1500;    // rules ke lastEarnAt gap se match — double-credit rokta hai

exports.handler = async (event) => {
  try {
    const params = event.queryStringParameters || {};
    const { userid, secret, type } = params;

    // 1) Secret verify — Adsgram ka Reward URL call unsigned hota hai,
    //    isliye apna khud ka secret hi security layer hai.
    if (!secret || secret !== process.env.REWARD_SECRET) {
      return { statusCode: 403, body: "Forbidden" };
    }

    if (!userid) {
      return { statusCode: 400, body: "Missing userid" };
    }

    const appUid = "tg_" + userid; // tumhare app ka existing uid format
    const amount = REWARD_AMOUNTS[type] || REWARD_AMOUNTS.default;
    const now = Date.now();

    const userRef = db.ref("users/" + appUid);

    const txnResult = await userRef.transaction((cur) => {
      if (cur === null) {
        cur = { pts: 0, today: 0, lastEarnAt: 0 };
      }
      const lastEarnAt = cur.lastEarnAt || 0;

      // Bahut jaldi dobara call aayi (duplicate/replay) — abort, credit mat do
      if (now - lastEarnAt < MIN_GAP_MS) {
        return; // undefined return = Firebase transaction abort karta hai
      }

      cur.pts = Math.min((cur.pts || 0) + amount, TOTAL_CAP);
      cur.today = Math.min((cur.today || 0) + amount, DAILY_CAP);
      cur.lastEarnAt = now;
      return cur;
    });

    if (!txnResult.committed) {
      return { statusCode: 200, body: "Skipped (duplicate/too soon)" };
    }

    return { statusCode: 200, body: "OK — credited " + amount + " pts to " + appUid };
  } catch (err) {
    console.error("reward function error:", err);
    return { statusCode: 500, body: "Server error" };
  }
};
