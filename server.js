import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import cors from "cors";
import admin from "firebase-admin";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Firebase
const firebaseConfig = JSON.parse(process.env.FIREBASE_CONFIG);
admin.initializeApp({
  credential: admin.credential.cert(firebaseConfig)
});

const db = admin.firestore();

// ================= JWT =================
function generateToken(user) {
  return jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send("No token");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).send("Invalid token");
  }
}

// ================= SIGNUP =================
app.post("/signup", async (req, res) => {
  const { name, password, image } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  await db.collection("teachers").add({
    name,
    password: hashed,
    image,
    paid: false,
    active: false
  });

  res.send("تم إنشاء الحساب");
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  const { name, password } = req.body;

  const snapshot = await db.collection("teachers")
    .where("name", "==", name).get();

  if (snapshot.empty) return res.send("المستخدم غير موجود");

  const doc = snapshot.docs[0];
  const user = doc.data();

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.send("كلمة المرور غلط");

  if (!user.active) return res.send("الحساب غير مفعل");

  const token = generateToken({ id: doc.id, name });

  res.json({ token });
});

// ================= PAYMENT =================
app.post("/pay", auth, async (req, res) => {
  await db.collection("teachers").doc(req.user.id).update({
    paid: true
  });
  res.send("تم تسجيل التحويل");
});

// ================= ADMIN =================
app.post("/admin-login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USERNAME &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = generateToken({ admin: true });
    return res.json({ token });
  }

  res.send("بيانات غلط");
});

// ================= GET USERS =================
app.get("/teachers", async (req, res) => {
  const snapshot = await db.collection("teachers").get();
  const data = snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data()
  }));
  res.json(data);
});

// ================= ACTIVATE =================
app.post("/activate/:id", async (req, res) => {
  await db.collection("teachers").doc(req.params.id).update({
    active: true
  });
  res.send("تم التفعيل");
});

app.listen(3000, () => console.log("Server running"));
