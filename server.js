const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json({ limit: "10kb" }));

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "keys.json");

if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 24) {
  throw new Error("Set ADMIN_TOKEN to a random secret of at least 24 characters.");
}

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "[]", "utf8");

app.use(express.static(path.join(__dirname, "public")));

function readKeys() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeKeys(keys) {
  const temp = DB_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(keys, null, 2), "utf8");
  fs.renameSync(temp, DB_FILE);
}

function requireAdmin(req, res, next) {
  const header = req.get("Authorization") || "";
  const supplied = header.startsWith("Bearer ") ? header.slice(7) : "";
  const a = Buffer.from(supplied);
  const b = Buffer.from(ADMIN_TOKEN);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Create a new key. Admin-only.
app.post("/api/keys", requireAdmin, (req, res) => {
  const keys = readKeys();
  const key = "MYKEY-" + crypto.randomBytes(18).toString("hex");
  const record = {
    key,
    enabled: true,
    createdAt: new Date().toISOString()
  };
  keys.push(record);
  writeKeys(keys);
  res.status(201).json(record);
});

// List keys. Admin-only.
app.get("/api/keys", requireAdmin, (req, res) => {
  res.json(readKeys().map(({ key, enabled, createdAt }) => ({
    key, enabled, createdAt
  })));
});

// Enable or disable a key. Admin-only.
app.patch("/api/keys/:key", requireAdmin, (req, res) => {
  if (typeof req.body.enabled !== "boolean") {
    return res.status(400).json({ error: "enabled must be a boolean" });
  }
  const keys = readKeys();
  const record = keys.find(item => item.key === req.params.key);
  if (!record) return res.status(404).json({ error: "Key not found" });

  record.enabled = req.body.enabled;
  writeKeys(keys);
  res.json({ key: record.key, enabled: record.enabled });
});

// Validate a key. Public endpoint; never returns the stored key list.
app.post("/api/validate", (req, res) => {
  const key = req.body && req.body.key;
  if (typeof key !== "string" || key.length > 100) {
    return res.status(400).json({ valid: false });
  }

  const record = readKeys().find(item => item.key === key);
  res.json({ valid: Boolean(record && record.enabled) });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Key system listening on port ${PORT}`);
});
