// EarnZone — Monetag Postback receiver (v3 — Adsgram se Monetag mein switch)
//
// Yeh function sirf itna karta hai — "haan, is user ne genuinely rewarded ad
// dekh li" — aur Firebase mein ek chhota sa timestamp flag (adVerifiedAt)
// likh deta hai. Asli reward-calculation (spin wheel, scratch card, slot
// machine ka random result) client-side hi hota hai, admin panel ki values
// se — bas ab woh sirf tab commit hoga jab Firebase Rules ko ek fresh,
// unused adVerifiedAt flag milega.
//
// Monetag apna postback call GET request se bhejta hai, jisme hum khud
// apna 'secret' query param add karte hain (Monetag SSP dashboard mein
// postback URL configure karte waqt). Macros ({ymid}, {reward_event_type}
// waghera) Monetag khud replace karke bhejta hai — inhe hum apni Netlify
// function ke URL mein query params ki tarah likhte hain.
//
// Postback URL jo Monetag dashboard mein daalni hai:
// https://tumhari-site.netlify.app/.netlify/functions/reward?ymid={ymid}&event={event_type}&reward={reward_event_type}&secret=TUMHARA_SECRET

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

exports.handler = async (event) => {
  try {
    const params = event.queryStringParameters || {};
    const { ymid, secret, reward } = params;

    // Secret verify — Monetag ka postback call unsigned hota hai,
    // isliye apna khud ka secret hi security layer hai.
    if (!secret || secret !== process.env.REWARD_SECRET) {
      return { statusCode: 403, body: "Forbidden" };
    }

    if (!ymid) {
      return { statusCode: 400, body: "Missing ymid" };
    }

    // ✅ reward_event_type check: Monetag ki official values "yes" (paid/valid)
    // ya "no" (non-paid/fraud/invalid traffic) hoti hain — "no" par credit mat do.
    if (reward === "no") {
      return { statusCode: 200, body: "Ignored — reward_event_type=no for " + ymid };
    }

    // ✅ ymid hi hamara appUid hai — game mein show ad call karte waqt
    // hum ymid: getUserId() pass karte hain, jo already 'tg_<telegramId>'
    // format mein hai. Isliye yahan koi prefix jodne ki zaroorat nahi.
    const appUid = ymid;

    // Sirf ek flag likho — Admin SDK Firebase Rules ko bypass karta hai,
    // isliye yeh write hamesha safal hoga, chahe client ke liye woh
    // field locked ho.
    await db.ref("users/" + appUid).update({
      adVerifiedAt: admin.database.ServerValue.TIMESTAMP,
    });

    return { statusCode: 200, body: "OK — ad verified for " + appUid };
  } catch (err) {
    console.error("reward function error:", err);
    return { statusCode: 500, body: "Server error" };
  }
};
