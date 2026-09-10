const crypto = require("crypto");

const SESSION_TTL_SEC = 60 * 60 * 24 * 7;
const ADMIN_GATE_ID = "__admin_gate__";
const ADMIN_GATE_STAMP = "admin-fixed-v1";

function sessionSecret() {
  return (
    process.env.ACCESS_TOKEN_SECRET ||
    process.env.ADMIN_SECRET ||
    "dev-insecure-secret"
  );
}

function getAdminGatePassword() {
  return String(
    process.env.ADMIN_GATE_PASSWORD || process.env.ADMIN_SECRET || ""
  ).trim();
}

function safeEqualString(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  try {
    return crypto.timingSafeEqual(x, y);
  } catch {
    return false;
  }
}

function matchesAdminGatePassword(password) {
  const expected = getAdminGatePassword();
  if (!expected || !password) return false;
  return safeEqualString(password, expected);
}

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromB64url(input) {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
  const s = input.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return Buffer.from(s, "base64").toString("utf8");
}

function sign(payload) {
  return crypto
    .createHmac("sha256", sessionSecret())
    .update(payload)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createSessionToken(item) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SEC;
  const body = `${item.id}|${item.updatedAt}|${exp}`;
  return `${b64url(body)}.${sign(body)}`;
}

function createAdminGateToken() {
  return createSessionToken({
    id: ADMIN_GATE_ID,
    updatedAt: ADMIN_GATE_STAMP,
  });
}

function parseSessionToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [bodyB64, sig] = parts;
  let body;
  try {
    body = fromB64url(bodyB64);
  } catch {
    return null;
  }
  if (sign(body) !== sig) return null;
  const segs = body.split("|");
  if (segs.length !== 3) return null;
  const [id, updatedAt, expStr] = segs;
  const exp = Number(expStr);
  if (!id || !updatedAt || !Number.isFinite(exp)) return null;
  if (exp < Math.floor(Date.now() / 1000)) return null;
  return { id, updatedAt, exp };
}

function isAdminGateSession(parsed) {
  return (
    parsed &&
    parsed.id === ADMIN_GATE_ID &&
    String(parsed.updatedAt) === ADMIN_GATE_STAMP
  );
}

function requireAdmin(req) {
  const expected = process.env.ADMIN_SECRET || "";
  if (!expected) return { ok: false, status: 500, error: "Chưa cấu hình ADMIN_SECRET trên Vercel" };
  const header = req.headers.authorization || req.headers.Authorization || "";
  const bearer = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const alt = (req.headers["x-admin-secret"] || "").trim();
  const got = bearer || alt;
  if (!got || got.length !== expected.length) {
    return { ok: false, status: 401, error: "ADMIN_SECRET không đúng" };
  }
  try {
    const match = crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected));
    if (!match) return { ok: false, status: 401, error: "ADMIN_SECRET không đúng" };
  } catch {
    return { ok: false, status: 401, error: "ADMIN_SECRET không đúng" };
  }
  return { ok: true };
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === "object") {
      resolve(req.body);
      return;
    }
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 1e6) reject(new Error("Body quá lớn"));
    });
    req.on("end", () => {
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
}

module.exports = {
  SESSION_TTL_SEC,
  ADMIN_GATE_ID,
  createSessionToken,
  createAdminGateToken,
  parseSessionToken,
  isAdminGateSession,
  matchesAdminGatePassword,
  getAdminGatePassword,
  requireAdmin,
  readJson,
  sendJson,
};
