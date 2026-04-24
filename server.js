require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");

const app = express();
app.use(express.json());

// Firebase init
const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// 🔐 Middleware
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send("No token");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).send("Invalid token");
  }
}

// 📝 Signin
app.post("/signin", async (req, res) => {
  const { name, password, image } = req.body;

  const hash = await bcrypt.hash(password, 10);

  const doc = await db.collection("teachers").add({
    name,
    password: hash,
    image,
    isPaid: false,
    isActive: false,
    createdAt: new Date()
  });

  res.send({ message: "Account created" });
});

// 🔑 Login
app.post("/login", async (req, res) => {
  const { name, password } = req.body;

  const snapshot = await db.collection("teachers")
    .where("name", "==", name)
    .get();

  if (snapshot.empty) return res.status(400).send("User not found");

  const doc = snapshot.docs[0];
  const user = doc.data();

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).send("Wrong password");

  const token = jwt.sign(
    { id: doc.id, name: user.name },
    process.env.JWT_SECRET
  );

  res.send({
    token,
    isActive: user.isActive,
    isPaid: user.isPaid,
    paymentNumber: process.env.PAYMENT_NUMBER,
    amount: process.env.PAYMENT_AMOUNT
  });
});

// 💰 تأكيد التحويل (المستخدم)
app.post("/mark-paid", auth, async (req, res) => {
  await db.collection("teachers").doc(req.user.id).update({
    isPaid: true
  });

  res.send("Marked as paid");
});

// 📊 Dashboard
app.get("/admin/stats", async (req, res) => {
  const snapshot = await db.collection("teachers").get();

  let total = snapshot.size;
  let paid = 0;

  snapshot.forEach(doc => {
    if (doc.data().isPaid) paid++;
  });

  res.send({ total, paid });
});

// ✅ تفعيل حساب
app.post("/admin/activate/:id", async (req, res) => {
  await db.collection("teachers").doc(req.params.id).update({
    isActive: true
  });

  res.send("Activated");
});

// 👀 كل المستخدمين
app.get("/admin/users", async (req, res) => {
  const snapshot = await db.collection("teachers").get();

  let users = [];
  snapshot.forEach(doc => {
    users.push({ id: doc.id, ...doc.data() });
  });

  res.send(users);
});

app.listen(process.env.PORT, () => {
  console.log("Server running...");
});
