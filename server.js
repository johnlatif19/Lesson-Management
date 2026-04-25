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

// ================= AUTH =================

// SIGNIN
app.post("/api/signin", async (req, res) => {
  const { name, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  await db.collection("teachers").add({
    name,
    password: hashed,
    status: "pending",
    paid: false,
    createdAt: Date.now()
  });

  res.json({ message: "Teacher created, waiting activation" });
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { name, password } = req.body;

  const snapshot = await db.collection("teachers").where("name", "==", name).get();

  if (snapshot.empty) return res.status(400).json({ msg: "User not found" });

  let user;
  snapshot.forEach(doc => user = { id: doc.id, ...doc.data() });

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

  await db.collection("teachers").doc(id).update({
    status: "active",
    paid: true
  });

  res.json({ message: "Activated" });
});

// REJECT
app.post("/api/admin/reject", auth, async (req, res) => {
  const { id } = req.body;

  await db.collection("teachers").doc(id).delete();

  res.json({ message: "Deleted" });
});

app.get("/payment", requirePaymentAccess, (req, res) => {
  res.sendFile(path.join(__dirname, "payment.html"));
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
