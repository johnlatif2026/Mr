const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");
const path = require("path");

require("dotenv").config();

const app = express();
app.use(express.json({ limit: "1mb" }));

// ---------- Helpers ----------
function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

function signToken(payload) {
  const secret = requireEnv("JWT_SECRET");
  return jwt.sign(payload, secret, { expiresIn: "7d" });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    const secret = requireEnv("JWT_SECRET");
    req.user = jwt.verify(token, secret);
    return next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---------- Serve pretty routes (/login, /dashboard) ----------
app.get("/login", (_req, res) => {
  return res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/dashboard", (_req, res) => {
  return res.sendFile(path.join(__dirname, "dashboard.html"));
});

// ---------- Firebase Admin (Firestore) ----------
function initFirebaseAdmin() {
  if (admin.apps.length) return;

  const svcJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const svcB64 = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;

  if (!svcJson && !svcB64) {
    throw new Error(
      "Missing FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_SERVICE_ACCOUNT_BASE64 in env"
    );
  }

  const serviceAccount = svcJson
    ? JSON.parse(svcJson)
    : JSON.parse(Buffer.from(svcB64, "base64").toString("utf8"));

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}
initFirebaseAdmin();

const db = admin.firestore();

// ---------- Firestore refs ----------
const profileRef = db.collection("site").doc("profile");
const scheduleRef = db.collection("site").doc("schedule");
const inquiriesCol = db.collection("inquiries");

// ---------- Email ----------
async function sendEmail({ subject, text }) {
  const host = requireEnv("SMTP_HOST");
  const port = Number(requireEnv("SMTP_PORT"));
  const user = requireEnv("SMTP_USER");
  const pass = requireEnv("SMTP_PASS");

  // دول اللي سألت عنهم:
  const to = requireEnv("MASTER_EMAIL_TO");      // الرسالة هتروح لمين
  const from = process.env.EMAIL_FROM || user;   // الرسالة جاية من مين (غالباً نفس SMTP_USER)

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
  });

  await transporter.sendMail({ from, to, subject, text });
}

// ---------- Telegram ----------
async function sendTelegram(text) {
  const token = requireEnv("TELEGRAM_BOT_TOKEN");
  const chatId = requireEnv("TELEGRAM_CHAT_ID");

  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text }),
  });

  if (!res.ok) {
    const t = await res.text();
    throw new Error("Telegram send failed: " + t);
  }
}

// ---------- Public API ----------
app.get("/api/public/profile", async (_req, res) => {
  const snap = await profileRef.get();
  if (!snap.exists) {
    return res.json({
      name: "مستر رياضة",
      bio: "اكتب نبذة هنا من الداشبورد",
      place: "—",
      phone: "—",
      age: null,
      photoUrl: "",
    });
  }
  return res.json(snap.data());
});

app.get("/api/public/schedule", async (_req, res) => {
  const snap = await scheduleRef.get();
  return res.json(snap.exists ? snap.data() : { items: [] });
});

app.post("/api/public/inquiry", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim();
  const phone = String(req.body.phone || "").trim();
  const message = String(req.body.message || "").trim();

  if (!name || !email || !message) {
    return res.status(400).json({ error: "name, email, message are required" });
  }

  const createdAt = new Date().toISOString();
  const doc = { name, email, phone, message, createdAt };

  await inquiriesCol.add(doc);

  const text =
    `طلب جديد من الموقع:\n` +
    `الاسم: ${name}\n` +
    `الإيميل: ${email}\n` +
    `الموبايل: ${phone || "-"}\n` +
    `الرسالة:\n${message}\n` +
    `الوقت: ${createdAt}`;

  // لو الإعدادات موجودة، يبعت — لو ناقصة، يتجاهل بدون ما يوقع السيرفر
  try { await sendEmail({ subject: "طلب جديد من موقع المستر", text }); } catch (e) {}
  try { await sendTelegram(text); } catch (e) {}

  return res.json({ ok: true });
});

// ---------- Auth (USERNAME/PASSWORD) ----------
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "").trim();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

// نعمل هاش داخلي للباسورد (بدل ما نخزن هاش في env) — أبسط للموبايل
// (أمنياً الأفضل تستخدم ADMIN_PASSWORD_HASH، لكن ده حل عملي سريع)
const ADMIN_PASSWORD_HASH = ADMIN_PASSWORD
  ? bcrypt.hashSync(ADMIN_PASSWORD, 10)
  : null;

app.post("/api/auth/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (!ADMIN_USERNAME || !ADMIN_PASSWORD_HASH) {
    return res.status(500).json({ error: "Admin env not configured" });
  }

  if (username !== ADMIN_USERNAME) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken({ role: "admin", username });
  return res.json({ token });
});

// ---------- Admin API (JWT protected) ----------
app.get("/api/admin/profile", authMiddleware, async (_req, res) => {
  const snap = await profileRef.get();
  return res.json(snap.exists ? snap.data() : {});
});

app.put("/api/admin/profile", authMiddleware, async (req, res) => {
  const payload = {
    name: String(req.body.name || "").trim(),
    bio: String(req.body.bio || "").trim(),
    place: String(req.body.place || "").trim(),
    phone: String(req.body.phone || "").trim(),
    photoUrl: String(req.body.photoUrl || "").trim(),
    age: req.body.age === null || req.body.age === "" ? null : Number(req.body.age),
    updatedAt: new Date().toISOString(),
  };

  if (!payload.name) return res.status(400).json({ error: "name is required" });

  await profileRef.set(payload, { merge: true });
  return res.json({ ok: true });
});

app.get("/api/admin/schedule", authMiddleware, async (_req, res) => {
  const snap = await scheduleRef.get();
  return res.json(snap.exists ? snap.data() : { items: [] });
});

app.put("/api/admin/schedule", authMiddleware, async (req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  const clean = items
    .map(x => ({
      day: String(x.day || "").trim(),
      time: String(x.time || "").trim(),
      location: String(x.location || "").trim(),
    }))
    .filter(x => x.day && x.time);

  await scheduleRef.set({ items: clean, updatedAt: new Date().toISOString() }, { merge: true });
  return res.json({ ok: true });
});

app.get("/api/admin/inquiries", authMiddleware, async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 25), 100);
  const snap = await inquiriesCol.orderBy("createdAt", "desc").limit(limit).get();
  const items = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  return res.json({ items });
});

// ---------- Vercel handler ----------
module.exports = (req, res) => app(req, res);

// ---------- Local dev ----------
if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log("Running on http://localhost:" + port));
    }
  
