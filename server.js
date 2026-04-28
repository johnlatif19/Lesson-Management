const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

function requirePaymentAccess(req, res, next) {
  const token = req.headers.authorization;

  if (!token) return res.redirect("/login.html");

  try {
    jwt.verify(token.split(" ")[1], JWT_SECRET);
    next();
  } catch {
    return res.redirect("/login.html");
  }
}

const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function sendTelegramMessage(message) {
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: "HTML"
      })
    });
  } catch (err) {
    console.error("Telegram Error:", err.message);
  }
}

// Firebase Init
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_CONFIG))
});

const db = admin.firestore();
const JWT_SECRET = process.env.JWT_SECRET;

// 🔐 Middleware
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send("No token");

  try {
    const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).send("Invalid token");
  }
}

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // true لو 465
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: `"Teacher System" <${process.env.SMTP_USER}>`,
      to,
      subject,
      html
    });
  } catch (err) {
    console.error("Email Error:", err.message);
  }
}

// ================= AUTH =================

// SIGNIN
app.post("/api/signin", async (req, res) => {
  const { name, password, email } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  // ✅ عدد المستخدمين
  const snapshot = await db.collection("teachers").get();
  const count = snapshot.size;

  // ✅ تحديد السعر
  let price = 150;
  let offer = false;

  if (count < 5) {
    price = 100;
    offer = true;
  }

  const now = Date.now();

  const docRef = await db.collection("teachers").add({
    name,
    email,
    password: hashed,
    status: "pending",
    paid: false,
    price,
    offer,
    offerStart: offer ? now : null,
    createdAt: now
  });

  await sendEmail(
    email,
    "تم استلام طلبك",
    `
      <h3>مرحباً ${name}</h3>
      <p>تم استلام طلب تسجيلك، وسيتم مراجعته قريباً.</p>
    `
  );

  const token = jwt.sign(
    { id: docRef.id, name },
    JWT_SECRET,
    { expiresIn: "7d" }
  );

  await sendTelegramMessage(
    `🆕 <b>تسجيل معلم جديد</b>\n👤 الاسم: ${name}\n🆔 المعرف: ${docRef.id}`
  );

  res.json({ message: "Teacher created", token });
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;

  let user = null;

  const snap1 = await db.collection("teachers").where("name", "==", name).get();

  if (!snap1.empty) {
    snap1.forEach(doc => user = { id: doc.id, ...doc.data() });
  } else {
    const snap2 = await db.collection("teachers").where("email", "==", name).get();

    if (!snap2.empty) {
      snap2.forEach(doc => user = { id: doc.id, ...doc.data() });
    }
  }

  if (!user) return res.status(400).json({ msg: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ msg: "Wrong password" });

  if (user.status !== "active") {
    return res.status(403).json({ msg: "Account not activated" });
  }

const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
res.json({ token, user });
});

// ================= ADMIN =================

// ADMIN LOGIN
app.post("/api/admin/login", (req, res) => {
  const { password } = req.body;

  if (password !== process.env.ADMIN_PASSWORD)
    return res.status(401).send("Wrong admin password");

  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "1d" });

  res.json({ token });
});

// GET USERS
app.get("/api/admin/users", auth, async (req, res) => {
  const snap = await db.collection("teachers").get();
  const users = [];

  snap.forEach(doc => users.push({ id: doc.id, ...doc.data() }));

  res.json(users);
});

// ACTIVATE USER
app.post("/api/admin/activate", auth, async (req, res) => {
  const { id } = req.body;

  const userRef = db.collection("teachers").doc(id);
  const userDoc = await userRef.get();

  if (!userDoc.exists) return res.status(404).send("User not found");

  const user = userDoc.data();

  const now = Date.now();
  const month = 30 * 24 * 60 * 60 * 1000;

  await userRef.update({
    status: "active",
    paid: true,
    activatedAt: now,
    expireAt: now + month
  });

  await sendEmail(
    user.email,
    "تم تفعيل حسابك",
    `
      <h2>🎉 مبروك ${user.name}</h2>
      <p>تم تفعيل حسابك ويمكنك تسجيل الدخول الآن.</p>
    `
  );

  res.json({ message: "Activated" });
});

// REJECT
app.post("/api/admin/reject", auth, async (req, res) => {
  const { id } = req.body;

  const userRef = db.collection("teachers").doc(id);
  const userDoc = await userRef.get();

  if (!userDoc.exists) {
    return res.status(404).send("User not found");
  }

  const user = userDoc.data();

  await sendEmail(
    user.email,
    "تم رفض الطلب",
    `
      <h3>مرحباً ${user.name}</h3>
      <p>نأسف، تم رفض طلب التسجيل الخاص بك.</p>
    `
  );

  // ✅ بدل الحذف
  await userRef.update({
    status: "rejected"
  });

  res.json({ message: "Rejected" });
});

app.get("/payment", requirePaymentAccess, (req, res) => {
  res.sendFile(path.join(__dirname, "payment.html"));
});

app.get("/api/me", async (req, res) => {
  const token = req.headers.authorization;

  if (!token) return res.status(401).json({ msg: "No token" });

  try {
    const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);

    const docRef = db.collection("teachers").doc(decoded.id);
    const doc = await docRef.get();

    if (!doc.exists) return res.status(404).json({ msg: "Not found" });

    const user = doc.data();

    // ✅ انتهاء الاشتراك
    if (user.expireAt && Date.now() > user.expireAt) {
      await docRef.update({
        status: "expired"
      });

      return res.json({
        id: doc.id,
        ...user,
        status: "expired"
      });
    }

    // ✅ انتهاء العرض بعد 3 شهور
    if (user.offer && user.offerStart) {
      const threeMonths = 90 * 24 * 60 * 60 * 1000;

      if (Date.now() - user.offerStart > threeMonths) {
        await docRef.update({
          offer: false,
          price: 150
        });

        user.offer = false;
        user.price = 150;
      }
    }

    res.json({ id: doc.id, ...user });

  } catch (e) {
    res.status(401).json({ msg: "Invalid token" });
  }
});

app.post("/api/admin/toggle", auth, async (req, res) => {
  const { id } = req.body;

  const userRef = db.collection("teachers").doc(id);
  const doc = await userRef.get();

  if (!doc.exists) return res.status(404).send("User not found");

  const user = doc.data();

  let newStatus = "active";

  if (user.status === "active") {
    newStatus = "stopped";
  } else if (user.status === "stopped") {
    newStatus = "active";
  }

  await userRef.update({
    status: newStatus
  });

  res.json({ message: "updated", status: newStatus });
});
    
const path = require("path");

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// أي حد يدخل /index يتحول لـ login
app.get("/index", (req, res) => {
  res.redirect("/login.html");
});

// حماية index.html
app.get("/index", (req, res) => {
  res.redirect("/login.html");
});

// الصفحة الرئيسية = login
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});


app.listen(3000, () => console.log("Server running"));
