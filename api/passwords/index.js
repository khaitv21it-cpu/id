const { isStoreConfigured } = require("../_lib/redis");
const {
  listPasswords,
  savePasswords,
  hashPassword,
  publicItem,
  newId,
} = require("../_lib/passwords");
const { requireAdmin, readJson, sendJson } = require("../_lib/session");

module.exports = async function handler(req, res) {
  if (!isStoreConfigured()) {
    sendJson(res, 503, { error: "Chưa kết nối Redis/KV trên Vercel" });
    return;
  }

  const admin = requireAdmin(req);
  if (!admin.ok) {
    sendJson(res, admin.status, { error: admin.error });
    return;
  }

  try {
    if (req.method === "GET") {
      const items = await listPasswords();
      sendJson(res, 200, { items: items.map(publicItem) });
      return;
    }

    if (req.method === "POST") {
      const body = await readJson(req);
      const password = String(body.password || "").trim();
      const label = String(body.label || "").trim();
      if (password.length < 4) {
        sendJson(res, 400, { error: "Mật khẩu tối thiểu 4 ký tự" });
        return;
      }
      const now = new Date().toISOString();
      const { salt, hash } = hashPassword(password);
      const item = {
        id: newId(),
        label: label || "Khách",
        salt,
        hash,
        createdAt: now,
        updatedAt: now,
      };
      const items = await listPasswords();
      items.push(item);
      await savePasswords(items);
      sendJson(res, 201, { item: publicItem(item) });
      return;
    }

    sendJson(res, 405, { error: "Method not allowed" });
  } catch (err) {
    sendJson(res, 500, { error: err.message || "Lỗi API mật khẩu" });
  }
};
