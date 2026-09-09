const crypto = require("crypto");
const { getRedis } = require("./redis");

const KEY = "web2m:access_passwords";

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(String(password), salt, 120000, 32, "sha256")
    .toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  if (!salt || !hash) return false;
  const next = crypto
    .pbkdf2Sync(String(password), salt, 120000, 32, "sha256")
    .toString("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(next, "hex"), Buffer.from(hash, "hex"));
  } catch {
    return false;
  }
}

async function listPasswords() {
  const redis = getRedis();
  if (!redis) return [];
  const raw = await redis.get(KEY);
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

async function savePasswords(items) {
  const redis = getRedis();
  if (!redis) throw new Error("Redis chưa cấu hình");
  await redis.set(KEY, items);
}

function publicItem(item) {
  return {
    id: item.id,
    label: item.label || "",
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
  };
}

function newId() {
  return crypto.randomBytes(8).toString("hex");
}

module.exports = {
  KEY,
  hashPassword,
  verifyPassword,
  listPasswords,
  savePasswords,
  publicItem,
  newId,
};
