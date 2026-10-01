// EarnZone — Telegram task reward (server-side)  [FIX Blocker #1: yeh function deploy mein missing tha]
//
// Game (verifyTask) is endpoint ko call karta hai:
//   POST /.netlify/functions/task-claim   Authorization: Bearer <Firebase ID token>   body: {taskId}
//
// Kya karta hai:
//   1. ID token verify -> caller uid (tg_<id>)
//   2. Ban check (deviceLock/{uid}.locked) -> 403 banned
//   3. appConfig/tasks se task dhoondhta hai (reward client se NAHI aata, admin config se aata hai)
//   4. task.url se channel/group nikalta hai aur Telegram getChatMember se membership check karta hai
//   5. users/{uid} par EK atomic transaction: doneTasks mein id nahi hai to hi pts/today/tasksDone/doneTasks
//      ek saath update hote hain (double-claim / race / partial-write nahi)
//
// Netlify env vars: TELEGRAM_BOT_TOKEN (bot us channel/group mein ADMIN/member hona chahiye),
//                   FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY, FIREBASE_DB_URL,
//                   ALLOWED_ORIGIN (comma-separated ho sakta hai)
//
// v2 (bug #7): private channel/group + non-Telegram tasks bhi support:
//   - task.chatId ("-100..." ya "@username") ho to wahi use hota hai (private invite link ke liye zaroori)
//   - t.me/c/<id>/<msg> links se chat id nikalta hai
//   - task.verify === "none" -> membership check nahi (website/bot/social task). Reward TRUST_TASK_MAX_PTS (default 50) se
//     capped, aur game ne "start" action bheja ho (>= 8s pehle) tabhi claim hota hai
//   - 422 errors ab alag reason dete hain: unverifiable-link | bot-not-in-chat | not-started
// Response: 200 {ok:true, reward, pts, today, tasksDone, doneTasks, already?}
//           400 bad-request | 401 no-token/bad-token | 403 banned/not-joined/bad-uid
//           404 task-not-found / user-missing | 422 task verify nahi ho sakta (private link, bot channel mein nahi, reward invalid)

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

const MAX_TOTAL_PTS = 500000;   // game ke MAX_TOTAL_PTS jaisa
const MAX_TASK_REWARD = 1000;
const TRUST_MIN_WAIT_MS = 8000;   // verify:"none" task: start -> claim ke beech kam se kam itna gap
const TRUST_TASK_MAX_PTS = Math.max(1, Number(process.env.TRUST_TASK_MAX_PTS) || 50);   // ek task ka upper cap (admin galti se bada number daale to bhi safe)

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

// Admin ne tasks array ya object dono tarah store kiye ho sakte hain (aur {_empty:true})
function toTaskList(v) {
  if (!v || typeof v !== "object" || v._empty === true) return [];
  return (Array.isArray(v) ? v : Object.values(v)).filter((t) => t && typeof t === "object");
}

// task.chatId / task.url se Telegram chat_id nikalo.
// Private invite links (t.me/+xxx, joinchat) se chat id nahi milta -> admin ko task.chatId (-100...) dena hoga.
function chatIdFromTask(task) {
  if (typeof task.chatId === "string") {
    const c = task.chatId.trim();
    if (/^-100[0-9]{5,15}$/.test(c)) return c;
    if (/^@[A-Za-z][A-Za-z0-9_]{4,31}$/.test(c)) return c;
  }
  let u;
  try { u = new URL(String(task.url || "").trim()); } catch (_) { return null; }
  if (u.protocol !== "https:" || !/^(t|telegram)\.me$/i.test(u.hostname)) return null;
  const parts = u.pathname.split("/").filter(Boolean);
  const first = parts[0] || "";
  // Private channel/group post link: t.me/c/<internalId>/<msgId>
  if (first === "c" && /^[0-9]{5,15}$/.test(parts[1] || "")) return "-100" + parts[1];
  if (!/^[A-Za-z][A-Za-z0-9_]{4,31}$/.test(first)) return null;   // '+abc' jaise private invite yahin reject
  // Telegram ke reserved paths (username nahi hain) — verify nahi ho sakte
  if (/^(joinchat|addlist|addstickers|addemoji|share|proxy|socks|setlanguage|login|iv|boost|invoice|bg|c|s|m)$/i.test(first)) return null;
  if (/bot$/i.test(first)) return null;   // bot link (t.me/xyz_bot) — membership hota hi nahi
  return "@" + first;
}

async function isMember(botToken, chatId, tgUserId) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    const r = await fetch("https://api.telegram.org/bot" + botToken + "/getChatMember", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, user_id: Number(tgUserId) }),
      signal: ctrl.signal,
    });
    const j = await r.json().catch(() => ({}));
    if (!j.ok) {
      const why = String(j.description || "telegram-error").slice(0, 120);
      // Bot us chat mein nahi / chat nahi mila / bot ko member list dekhne ka haq nahi -> admin ko fix karna hai
      const botIssue = /chat not found|not enough rights|member list is inaccessible|bot is not a member|CHAT_ADMIN_REQUIRED|kicked/i.test(why);
      return { verifiable: false, joined: false, why, botIssue };
    }
    const st = j.result && j.result.status;
    const joined = st === "creator" || st === "administrator" || st === "member" || (st === "restricted" && j.result.is_member === true);
    return { verifiable: true, joined };
  } catch (e) {
    return { verifiable: false, joined: false, why: "network" };
  } finally { clearTimeout(timer); }
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
  const headers = cors(event.headers && (event.headers.origin || event.headers.Origin), "Content-Type, Authorization, X-Firebase-AppCheck");
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers, body: "" };
  if (event.httpMethod !== "POST") return reply(405, headers, { error: "method" });
  if (!(await appCheckOk(event))) return { statusCode: 401, headers, body: JSON.stringify({ error: "app-check" }) };

  try {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    if (!botToken) return reply(500, headers, { error: "server-config" });

    // 1) Auth
    const m = ((event.headers && (event.headers.authorization || event.headers.Authorization)) || "").match(/^Bearer (.+)$/);
    if (!m) return reply(401, headers, { error: "no-token" });
    let decoded;
    try { decoded = await admin.auth().verifyIdToken(m[1]); }
    catch (_) { return reply(401, headers, { error: "bad-token" }); }
    const uid = decoded.uid;
    if (!/^tg_[0-9]{1,15}$/.test(uid)) return reply(403, headers, { error: "bad-uid" });
    const tgUserId = uid.slice(3);

    // 2) Input
    let body; try { body = JSON.parse(event.body || "{}"); } catch (_) { body = {}; }
    const taskId = typeof body.taskId === "string" ? body.taskId : "";
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(taskId)) return reply(400, headers, { error: "bad-task" });

    // 2b) "start" action: game Join dabate hi bhejta hai (sirf verify:"none" tasks ke liye kaam ka)
    if (body.action === "start") {
      const banS = (await db.ref("deviceLock/" + uid + "/locked").once("value")).val();
      if (banS === true) return reply(403, headers, { error: "banned" });
      const tk = toTaskList((await db.ref("appConfig/tasks").once("value")).val()).find((t) => String(t.id) === taskId);
      if (!tk) return reply(404, headers, { error: "task-not-found" });
      if (tk.verify === "none") {
        const sref = db.ref("taskStarts/" + uid + "/" + taskId);
        if (!(await sref.once("value")).exists()) await sref.set(Date.now());   // pehli baar ka time hi gine (reset se gap bypass na ho)
      }
      return reply(200, headers, { ok: true });
    }

    // 3) Ban check
    const ban = (await db.ref("deviceLock/" + uid + "/locked").once("value")).val();
    if (ban === true) return reply(403, headers, { error: "banned" });

    // 4) Task admin config se (reward/URL client par bharosa nahi)
    const tasks = toTaskList((await db.ref("appConfig/tasks").once("value")).val());
    const task = tasks.find((t) => String(t.id) === taskId);
    if (!task) return reply(404, headers, { error: "task-not-found" });
    const reward = Math.min(Math.round(Number(task.pts)), MAX_TASK_REWARD);
    if (!isFinite(reward) || reward <= 0) return reply(422, headers, { error: "bad-reward" });

    const trustCap = task.verify === "none" ? TRUST_TASK_MAX_PTS : MAX_TASK_REWARD;
    const effReward = Math.min(reward, trustCap);
    const userRef = db.ref("users/" + uid);
    const cur = (await userRef.once("value")).val();
    if (!cur || typeof cur.pts !== "number") return reply(404, headers, { error: "user-missing" });
    const curDone = Array.isArray(cur.doneTasks) ? cur.doneTasks : (cur.doneTasks && typeof cur.doneTasks === "object" ? Object.values(cur.doneTasks) : []);
    if (curDone.includes(taskId)) {
      return reply(200, headers, { ok: true, already: true, pts: cur.pts, today: Number(cur.today) || 0, tasksDone: Number(cur.tasksDone) || 0, doneTasks: curDone });
    }

    // 5) Verification
    const trust = task.verify === "none";
    if (trust) {
      // Non-Telegram / unverifiable task: admin ne explicitly "trust" mode diya. Reward cap + server-side start gap.
      const startedAt = Number((await db.ref("taskStarts/" + uid + "/" + taskId).once("value")).val()) || 0;
      if (!startedAt || Date.now() - startedAt < TRUST_MIN_WAIT_MS) return reply(422, headers, { error: "not-started" });
    } else {
      const chatId = chatIdFromTask(task);
      if (!chatId) return reply(422, headers, { error: "unverifiable-link" });
      const mem = await isMember(botToken, chatId, tgUserId);
      if (!mem.verifiable) {
        console.warn("task-claim: verify fail", taskId, mem.why);
        return reply(422, headers, { error: mem.botIssue ? "bot-not-in-chat" : "cannot-verify" });
      }
      if (!mem.joined) return reply(403, headers, { error: "not-joined" });
    }

    // 6) ATOMIC claim — doneTasks + pts + today + tasksDone ek hi transaction mein
    let outcome = "";
    const tx = await userRef.transaction((u) => {
      outcome = "";
      if (u === null || typeof u !== "object") return u;          // local cache khaali — SDK server value ke saath retry karega
      if (typeof u.pts !== "number") { outcome = "nouser"; return; }
      const done = Array.isArray(u.doneTasks) ? u.doneTasks.slice() : (u.doneTasks && typeof u.doneTasks === "object" ? Object.values(u.doneTasks) : []);
      if (done.includes(taskId)) { outcome = "already"; return; }   // return undefined = abort
      done.push(taskId);
      const give = Math.max(0, Math.min(effReward, MAX_TOTAL_PTS - u.pts));
      u.doneTasks = done;
      u.pts = u.pts + give;
      u.today = (typeof u.today === "number" && u.today >= 0 ? u.today : 0) + give;
      u.tasksDone = (typeof u.tasksDone === "number" && u.tasksDone >= 0 ? u.tasksDone : 0) + 1;
      outcome = "ok:" + give;
      return u;
    });

    const fin = tx.snapshot.val() || {};
    const finDone = Array.isArray(fin.doneTasks) ? fin.doneTasks : (fin.doneTasks && typeof fin.doneTasks === "object" ? Object.values(fin.doneTasks) : []);
    if (!tx.committed) {
      if (outcome === "already") return reply(200, headers, { ok: true, already: true, pts: fin.pts, today: Number(fin.today) || 0, tasksDone: Number(fin.tasksDone) || 0, doneTasks: finDone });
      return reply(404, headers, { error: "user-missing" });
    }
    return reply(200, headers, {
      ok: true, reward: Number(outcome.split(":")[1]) || 0,
      pts: fin.pts, today: fin.today, tasksDone: fin.tasksDone, doneTasks: finDone,
    });
  } catch (err) {
    console.error("task-claim error:", err && err.message);
    return reply(500, headers, { error: "server" });
  }
};
