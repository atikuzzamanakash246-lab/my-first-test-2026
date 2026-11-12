const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret-for-online-use";
const DATA_FILE = path.join(__dirname, "data", "skys-food.json");

function ensureDatabase() {
  const folder = path.dirname(DATA_FILE);
  if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    const products = [
      ["Classic Burger","Burgers","Juicy beef-style burger with fresh toppings.",180,"🍔"],
      ["Cheese Pizza","Pizza","Cheesy pizza with a crispy crust.",350,"🍕"],
      ["Chicken Sandwich","Snacks","Fresh and filling chicken sandwich.",150,"🥪"],
      ["Sushi Set","Asian","A delicious bite-sized favorite.",420,"🍣"],
      ["French Fries","Snacks","Golden, crispy potato fries.",100,"🍟"],
      ["Fried Chicken","Chicken","Crunchy outside, tender inside.",220,"🍗"],
      ["Creamy Pasta","Asian","Creamy and flavorful pasta.",250,"🍝"],
      ["Tacos","Snacks","Freshly filled tasty tacos.",190,"🌮"],
      ["Hot Dog","Snacks","Classic street-food favorite.",130,"🌭"],
      ["Pancakes","Desserts","Soft pancakes for a sweet treat.",160,"🥞"],
      ["Ice Cream","Desserts","Cool and creamy dessert.",90,"🍨"],
      ["Donut","Desserts","Sweet, soft and delicious.",80,"🍩"],
      ["Fresh Juice","Drinks","Refreshing seasonal fruit juice.",110,"🧃"]
    ].map((p, i) => ({
      id: i + 1, name: p[0], category: p[1], description: p[2],
      price: p[3], emoji: p[4], available: 1
    }));
    saveData({ users: [], products, orders: [], nextUserId: 1, nextProductId: 14, nextOrderId: 1 });
  }
}
function loadData() {
  ensureDatabase();
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}
function saveData(data) {
  const temp = DATA_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(data, null, 2), "utf8");
  fs.renameSync(temp, DATA_FILE);
}
ensureDatabase();

const appData = {
  read: loadData,
  write: saveData
};

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "100kb" }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 86400000 }
}));
app.use(express.static(path.join(__dirname, "public")));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please log in first." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin")
    return res.status(403).json({ error: "Admin access required." });
  next();
}

app.get("/api/session", (req, res) => res.json({ user: req.session.user || null }));

app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name?.trim() || !email?.trim() || !password || password.length < 8)
    return res.status(400).json({ error: "Enter your name, valid email and a password of at least 8 characters." });
  const data = appData.read();
  const normalizedEmail = email.trim().toLowerCase();
  if (data.users.some(u => u.email === normalizedEmail))
    return res.status(409).json({ error: "That email is already registered." });
  const hash = await bcrypt.hash(password, 10);
  const user = {
    id: data.nextUserId++, name: name.trim(), email: normalizedEmail,
    password_hash: hash, role: "customer", created_at: new Date().toISOString()
  };
  data.users.push(user);
  appData.write(data);
  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ user: req.session.user });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  const data = appData.read();
  const user = data.users.find(u => u.email === String(email || "").trim().toLowerCase());
  if (!user || !(await bcrypt.compare(password || "", user.password_hash)))
    return res.status(401).json({ error: "Email or password is incorrect." });
  req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ user: req.session.user });
});

app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get("/api/products", (req, res) => {
  const data = appData.read();
  res.json(data.products.filter(p => p.available).sort((a, b) => b.id - a.id)
    .map(({ id, name, category, description, price, emoji }) => ({ id, name, category, description, price, emoji })));
});

app.get("/api/orders", requireAuth, (req, res) => {
  const data = appData.read();
  res.json(data.orders.filter(o => o.user_id === req.session.user.id).sort((a, b) => b.id - a.id));
});

app.post("/api/orders", requireAuth, (req, res) => {
  const { items, customerName, phone, address, coupon } = req.body || {};
  if (!Array.isArray(items) || !items.length || !customerName?.trim() || !phone?.trim() || !address?.trim())
    return res.status(400).json({ error: "Add items and complete your delivery details." });
  const data = appData.read();
  let subtotal = 0;
  const normalized = [];
  for (const item of items) {
    const product = data.products.find(p => p.id === Number(item.id) && p.available);
    const qty = Math.max(1, Math.min(30, Number(item.qty) || 1));
    if (!product) return res.status(400).json({ error: "A selected product is unavailable." });
    subtotal += product.price * qty;
    normalized.push({ id: product.id, name: product.name, price: product.price, qty });
  }
  const discount = String(coupon || "").toUpperCase() === "SKY10" ? Math.round(subtotal * 0.10) : 0;
  const delivery_fee = 50;
  const total = subtotal - discount + delivery_fee;
  const order = {
    id: data.nextOrderId++, user_id: req.session.user.id,
    customer_name: customerName.trim(), phone: phone.trim(), address: address.trim(),
    items: normalized, items_json: JSON.stringify(normalized), subtotal, discount,
    delivery_fee, total, status: "Pending", created_at: new Date().toISOString()
  };
  data.orders.push(order);
  appData.write(data);
  res.json({ orderId: order.id, subtotal, discount, delivery_fee, total, status: "Pending" });
});

app.get("/api/admin/summary", requireAdmin, (req, res) => {
  const data = appData.read();
  res.json({
    products: data.products.length,
    orders: data.orders.length,
    revenue: data.orders.filter(o => o.status !== "Cancelled").reduce((sum, o) => sum + o.total, 0),
    customers: data.users.filter(u => u.role === "customer").length
  });
});

app.get("/api/admin/orders", requireAdmin, (req, res) => {
  const data = appData.read();
  res.json(data.orders.slice().sort((a, b) => b.id - a.id));
});

app.patch("/api/admin/orders/:id", requireAdmin, (req, res) => {
  const allowed = ["Pending", "Confirmed", "Preparing", "Out for delivery", "Delivered", "Cancelled"];
  if (!allowed.includes(req.body.status)) return res.status(400).json({ error: "Invalid order status." });
  const data = appData.read();
  const order = data.orders.find(o => o.id === Number(req.params.id));
  if (!order) return res.status(404).json({ error: "Order not found." });
  order.status = req.body.status;
  appData.write(data);
  res.json({ ok: true });
});

app.post("/api/admin/products", requireAdmin, (req, res) => {
  const { name, category, description, price, emoji } = req.body || {};
  if (!name?.trim() || !category?.trim() || !description?.trim() || !Number.isFinite(Number(price)) || Number(price) <= 0)
    return res.status(400).json({ error: "Please complete all product fields." });
  const data = appData.read();
  const product = {
    id: data.nextProductId++, name: name.trim(), category: category.trim(),
    description: description.trim(), price: Math.round(Number(price)),
    emoji: emoji || "🍽️", available: 1
  };
  data.products.push(product);
  appData.write(data);
  res.json({ id: product.id });
});

app.patch("/api/admin/products/:id/availability", requireAdmin, (req, res) => {
  const data = appData.read();
  const product = data.products.find(p => p.id === Number(req.params.id));
  if (!product) return res.status(404).json({ error: "Product not found." });
  product.available = req.body.available ? 1 : 0;
  appData.write(data);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`SKY's Food running at http://localhost:${PORT}`));
