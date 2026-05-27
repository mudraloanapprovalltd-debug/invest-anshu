// ═══════════════════════════════════════════════════════════════════
//  INVEST WITH ANSHU - COMPLETE BACKEND SERVER
//  Node.js + Express + NeDB (file-based DB) + JWT Auth
// ═══════════════════════════════════════════════════════════════════

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Datastore = require("@seald-io/nedb");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "default_secret_change_me";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "Anshu123";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Anshu@2026";

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ─── DATABASE SETUP ────────────────────────────────────────────────
const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const db = {
  users: new Datastore({ filename: path.join(dataDir, "users.db"), autoload: true }),
  investments: new Datastore({ filename: path.join(dataDir, "investments.db"), autoload: true }),
  deposits: new Datastore({ filename: path.join(dataDir, "deposits.db"), autoload: true }),
  withdrawals: new Datastore({ filename: path.join(dataDir, "withdrawals.db"), autoload: true }),
  plans: new Datastore({ filename: path.join(dataDir, "plans.db"), autoload: true }),
  settings: new Datastore({ filename: path.join(dataDir, "settings.db"), autoload: true }),
};

db.users.ensureIndex({ fieldName: "username", unique: true });
db.users.ensureIndex({ fieldName: "email", unique: true });

// ─── SEED DEFAULT DATA ─────────────────────────────────────────────
async function seedDefaults() {
  // Default plans
  const planCount = await db.plans.countAsync({});
  if (planCount === 0) {
    const defaultPlans = [
      { name: "Starter BTC", asset: "BTC", minInvest: 500, maxInvest: 5000, returnPct: 15, durationMins: 60, color: "#F7931A", active: true, createdAt: new Date() },
      { name: "USDT Stable", asset: "USDT", minInvest: 1000, maxInvest: 20000, returnPct: 20, durationMins: 240, color: "#26A17B", active: true, createdAt: new Date() },
      { name: "Gold Premium", asset: "GOLD", minInvest: 2000, maxInvest: 50000, returnPct: 25, durationMins: 720, color: "#D4AF37", active: true, createdAt: new Date() },
      { name: "Forex Elite", asset: "FOREX", minInvest: 5000, maxInvest: 100000, returnPct: 35, durationMins: 1440, color: "#A855F7", active: true, createdAt: new Date() },
    ];
    await db.plans.insertAsync(defaultPlans);
    console.log("✅ Seeded default plans");
  }

  // Default settings
  const settingsCount = await db.settings.countAsync({ key: "main" });
  if (settingsCount === 0) {
    await db.settings.insertAsync({
      key: "main",
      paymentInfo: {
        accountName: "Anshu Kumar",
        accountNumber: "1234567890",
        ifsc: "SBIN0001234",
        bankName: "State Bank of India",
        upiId: "anshu@paytm",
      },
      contact: {
        email: "support@investwithanshu.com",
        mobile: "+91 98765 43210",
        address: "Mumbai, Maharashtra, India",
        weekdayLabel: "Mon - Sat",
        weekdayHours: "9:00 AM - 8:00 PM",
        sundayHours: "10:00 AM - 4:00 PM",
        supportNote: "We respond within 1 hour during business hours.",
      },
    });
    console.log("✅ Seeded default settings");
  }
}
seedDefaults();

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────
function userAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== "user") return res.status(403).json({ error: "Forbidden" });
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

function adminAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== "admin") return res.status(403).json({ error: "Admin only" });
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ─── HELPER: GET FULL USER PROFILE ─────────────────────────────────
async function getUserProfile(userId) {
  const user = await db.users.findOneAsync({ _id: userId });
  if (!user) return null;
  const investments = await db.investments.findAsync({ userId }).sort({ createdAt: -1 });
  const deposits = await db.deposits.findAsync({ userId }).sort({ createdAt: -1 });
  const withdrawals = await db.withdrawals.findAsync({ userId }).sort({ createdAt: -1 });
  delete user.password;
  return { ...user, investments, deposits, withdrawals };
}

// ═══════════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ═══════════════════════════════════════════════════════════════════

app.get("/api/plans", async (req, res) => {
  const plans = await db.plans.findAsync({ active: true }).sort({ minInvest: 1 });
  res.json(plans);
});

app.get("/api/settings/public", async (req, res) => {
  const s = await db.settings.findOneAsync({ key: "main" });
  res.json({ paymentInfo: s?.paymentInfo || {}, contact: s?.contact || {} });
});

// ═══════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, username, email, mobile, password } = req.body;
    if (!name || !username || !email || !mobile || !password)
      return res.status(400).json({ error: "All fields required" });
    if (password.length < 6) return res.status(400).json({ error: "Password too short" });

    const existsUser = await db.users.findOneAsync({ username: username.toLowerCase() });
    if (existsUser) return res.status(400).json({ error: "Username already taken" });
    const existsEmail = await db.users.findOneAsync({ email: email.toLowerCase() });
    if (existsEmail) return res.status(400).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const newUser = await db.users.insertAsync({
      name,
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      mobile,
      password: hash,
      wallet: 0,
      bankDetails: {},
      createdAt: new Date(),
    });

    const token = jwt.sign({ id: newUser._id, role: "user" }, JWT_SECRET, { expiresIn: "30d" });
    const profile = await getUserProfile(newUser._id);
    res.json({ token, user: profile });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username & password required" });
    const user = await db.users.findOneAsync({ username: username.toLowerCase() });
    if (!user) return res.status(400).json({ error: "Invalid username or password" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid username or password" });

    const token = jwt.sign({ id: user._id, role: "user" }, JWT_SECRET, { expiresIn: "30d" });
    const profile = await getUserProfile(user._id);
    res.json({ token, user: profile });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/auth/admin-login", async (req, res) => {
  const { username, password } = req.body;
  // Check stored admin creds first (from settings), else default
  const s = await db.settings.findOneAsync({ key: "main" });
  const adminUser = s?.adminUsername || ADMIN_USERNAME;
  const adminPass = s?.adminPassword || ADMIN_PASSWORD;
  if (username !== adminUser || password !== adminPass)
    return res.status(401).json({ error: "Invalid admin credentials" });
  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

// ═══════════════════════════════════════════════════════════════════
//  USER ROUTES (authenticated)
// ═══════════════════════════════════════════════════════════════════

app.get("/api/user/me", userAuth, async (req, res) => {
  const profile = await getUserProfile(req.userId);
  if (!profile) return res.status(404).json({ error: "User not found" });
  res.json(profile);
});

app.put("/api/user/bank", userAuth, async (req, res) => {
  await db.users.updateAsync({ _id: req.userId }, { $set: { bankDetails: req.body } });
  res.json({ success: true });
});

app.put("/api/user/password", userAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: "Password too short" });
  const user = await db.users.findOneAsync({ _id: req.userId });
  const match = await bcrypt.compare(oldPassword, user.password);
  if (!match) return res.status(400).json({ error: "Current password is incorrect" });
  const hash = await bcrypt.hash(newPassword, 10);
  await db.users.updateAsync({ _id: req.userId }, { $set: { password: hash } });
  res.json({ success: true });
});

// ─── DEPOSITS ──────────────────────────────────────────────────────
app.post("/api/deposits", userAuth, async (req, res) => {
  const { amount, txnId } = req.body;
  if (!amount || amount < 100) return res.status(400).json({ error: "Minimum deposit ₹100" });
  if (!txnId) return res.status(400).json({ error: "Transaction ID required" });
  const user = await db.users.findOneAsync({ _id: req.userId });
  await db.deposits.insertAsync({
    userId: req.userId,
    userName: user.name,
    userUsername: user.username,
    amount: Number(amount),
    txnId,
    status: "pending",
    createdAt: new Date(),
  });
  res.json({ success: true });
});

// ─── INVESTMENTS ───────────────────────────────────────────────────
app.post("/api/investments", userAuth, async (req, res) => {
  const { planId, amount } = req.body;
  const plan = await db.plans.findOneAsync({ _id: planId, active: true });
  if (!plan) return res.status(400).json({ error: "Plan not found" });
  if (amount < plan.minInvest || amount > plan.maxInvest)
    return res.status(400).json({ error: `Amount must be ₹${plan.minInvest} – ₹${plan.maxInvest}` });
  const user = await db.users.findOneAsync({ _id: req.userId });
  if (user.wallet < amount) return res.status(400).json({ error: "Insufficient wallet balance" });

  const profit = Math.round((amount * plan.returnPct) / 100);
  const maturesAt = new Date(Date.now() + plan.durationMins * 60 * 1000);
  const durLabel = plan.durationMins >= 60
    ? `${plan.durationMins / 60} Hour${plan.durationMins / 60 > 1 ? "s" : ""}`
    : `${plan.durationMins} Minutes`;

  await db.users.updateAsync({ _id: req.userId }, { $inc: { wallet: -amount } });
  await db.investments.insertAsync({
    userId: req.userId,
    userName: user.name,
    userUsername: user.username,
    planId,
    planName: plan.name,
    asset: plan.asset,
    amount: Number(amount),
    profit,
    returnPct: plan.returnPct,
    durationMins: plan.durationMins,
    duration: durLabel,
    status: "running",
    createdAt: new Date(),
    maturesAt,
  });
  res.json({ success: true });
});

// ─── WITHDRAWALS ───────────────────────────────────────────────────
app.post("/api/withdrawals", userAuth, async (req, res) => {
  const { amount, method, accountDetails } = req.body;
  if (!amount || amount < 100) return res.status(400).json({ error: "Minimum withdrawal ₹100" });
  const user = await db.users.findOneAsync({ _id: req.userId });
  if (user.wallet < amount) return res.status(400).json({ error: "Insufficient wallet balance" });

  // Lock funds immediately (deduct from wallet)
  await db.users.updateAsync({ _id: req.userId }, { $inc: { wallet: -amount } });
  await db.withdrawals.insertAsync({
    userId: req.userId,
    userName: user.name,
    userUsername: user.username,
    amount: Number(amount),
    method,
    accountDetails,
    status: "pending",
    createdAt: new Date(),
  });
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════════

app.get("/api/admin/overview", adminAuth, async (req, res) => {
  const users = await db.users.countAsync({});
  const pendingDeposits = await db.deposits.countAsync({ status: "pending" });
  const pendingWithdrawals = await db.withdrawals.countAsync({ status: "pending" });
  const allDeposits = await db.deposits.findAsync({ status: "approved" });
  const allWithdrawals = await db.withdrawals.findAsync({ status: "approved" });
  const allInvestments = await db.investments.findAsync({});
  const totalDeposited = allDeposits.reduce((s, d) => s + d.amount, 0);
  const totalWithdrawn = allWithdrawals.reduce((s, w) => s + w.amount, 0);
  const totalInvested = allInvestments.reduce((s, i) => s + i.amount, 0);
  res.json({ users, pendingDeposits, pendingWithdrawals, totalDeposited, totalWithdrawn, totalInvested });
});

// ─── USERS ─────────────────────────────────────────────────────────
app.get("/api/admin/users", adminAuth, async (req, res) => {
  const users = await db.users.findAsync({}).sort({ createdAt: -1 });
  users.forEach(u => delete u.password);
  res.json(users);
});

app.put("/api/admin/users/:id/wallet", adminAuth, async (req, res) => {
  const { wallet } = req.body;
  await db.users.updateAsync({ _id: req.params.id }, { $set: { wallet: Number(wallet) } });
  res.json({ success: true });
});

app.delete("/api/admin/users/:id", adminAuth, async (req, res) => {
  await db.users.removeAsync({ _id: req.params.id });
  await db.investments.removeAsync({ userId: req.params.id }, { multi: true });
  await db.deposits.removeAsync({ userId: req.params.id }, { multi: true });
  await db.withdrawals.removeAsync({ userId: req.params.id }, { multi: true });
  res.json({ success: true });
});

// ─── DEPOSITS ──────────────────────────────────────────────────────
app.get("/api/admin/deposits", adminAuth, async (req, res) => {
  const deposits = await db.deposits.findAsync({}).sort({ createdAt: -1 });
  res.json(deposits);
});

app.put("/api/admin/deposits/:id", adminAuth, async (req, res) => {
  const { status } = req.body;
  const dep = await db.deposits.findOneAsync({ _id: req.params.id });
  if (!dep) return res.status(404).json({ error: "Not found" });
  if (dep.status !== "pending") return res.status(400).json({ error: "Already processed" });
  await db.deposits.updateAsync({ _id: req.params.id }, { $set: { status, processedAt: new Date() } });
  if (status === "approved") {
    await db.users.updateAsync({ _id: dep.userId }, { $inc: { wallet: dep.amount } });
  }
  res.json({ success: true });
});

// ─── WITHDRAWALS ───────────────────────────────────────────────────
app.get("/api/admin/withdrawals", adminAuth, async (req, res) => {
  const withdrawals = await db.withdrawals.findAsync({}).sort({ createdAt: -1 });
  res.json(withdrawals);
});

app.put("/api/admin/withdrawals/:id", adminAuth, async (req, res) => {
  const { status } = req.body;
  const w = await db.withdrawals.findOneAsync({ _id: req.params.id });
  if (!w) return res.status(404).json({ error: "Not found" });
  if (w.status !== "pending") return res.status(400).json({ error: "Already processed" });
  await db.withdrawals.updateAsync({ _id: req.params.id }, { $set: { status, processedAt: new Date() } });
  if (status === "rejected") {
    // Refund the user
    await db.users.updateAsync({ _id: w.userId }, { $inc: { wallet: w.amount } });
  }
  res.json({ success: true });
});

// ─── INVESTMENTS ───────────────────────────────────────────────────
app.get("/api/admin/investments", adminAuth, async (req, res) => {
  const investments = await db.investments.findAsync({}).sort({ createdAt: -1 });
  res.json(investments);
});

// ─── PLANS ─────────────────────────────────────────────────────────
app.get("/api/admin/plans", adminAuth, async (req, res) => {
  const plans = await db.plans.findAsync({}).sort({ minInvest: 1 });
  res.json(plans);
});

app.post("/api/admin/plans", adminAuth, async (req, res) => {
  const p = req.body;
  await db.plans.insertAsync({
    name: p.name,
    asset: p.asset,
    minInvest: Number(p.minInvest),
    maxInvest: Number(p.maxInvest),
    returnPct: Number(p.returnPct),
    durationMins: Number(p.durationMins),
    color: p.color || "#D4AF37",
    active: p.active !== false,
    createdAt: new Date(),
  });
  res.json({ success: true });
});

app.put("/api/admin/plans/:id", adminAuth, async (req, res) => {
  const { _id, createdAt, ...updates } = req.body;
  ["minInvest", "maxInvest", "returnPct", "durationMins"].forEach(k => {
    if (updates[k] !== undefined) updates[k] = Number(updates[k]);
  });
  await db.plans.updateAsync({ _id: req.params.id }, { $set: updates });
  res.json({ success: true });
});

app.delete("/api/admin/plans/:id", adminAuth, async (req, res) => {
  await db.plans.removeAsync({ _id: req.params.id });
  res.json({ success: true });
});

// ─── SETTINGS ──────────────────────────────────────────────────────
app.put("/api/admin/settings/payment", adminAuth, async (req, res) => {
  await db.settings.updateAsync({ key: "main" }, { $set: { paymentInfo: req.body } }, { upsert: true });
  res.json({ success: true });
});

app.put("/api/admin/settings/contact", adminAuth, async (req, res) => {
  await db.settings.updateAsync({ key: "main" }, { $set: { contact: req.body } }, { upsert: true });
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════
//  BACKGROUND JOB: Auto-complete matured investments every 30s
// ═══════════════════════════════════════════════════════════════════
setInterval(async () => {
  try {
    const now = new Date();
    const matured = await db.investments.findAsync({ status: "running", maturesAt: { $lte: now } });
    for (const inv of matured) {
      const payout = inv.amount + inv.profit;
      await db.users.updateAsync({ _id: inv.userId }, { $inc: { wallet: payout } });
      await db.investments.updateAsync({ _id: inv._id }, { $set: { status: "completed", completedAt: now } });
      console.log(`✅ Investment ${inv._id} matured. Credited ₹${payout} to user ${inv.userUsername}`);
    }
  } catch (e) {
    console.error("Job error:", e);
  }
}, 30000);

// ─── SERVE FRONTEND ────────────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`\n🚀 Server running on http://localhost:${PORT}`);
  console.log(`👤 Admin login: ${ADMIN_USERNAME} / ${ADMIN_PASSWORD}\n`);
});