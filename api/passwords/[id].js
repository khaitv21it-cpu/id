const { isStoreConfigured } = require("../_lib/redis");
const {
  listPasswords,
  savePasswords,
  hashPassword,
  publicItem,
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

  const id = req.query.id;
  if (!id) {
    sendJson(res, 400, { error: "Thiếu id" });
    return;
  }

  try {
    const items = await listPasswords();
    const idx = items.findIndex((x) => String(x.id) === String(id));
    if (idx < 0) {
      sendJson(res, 404, { error: "Không tìm thấy mật khẩu" });
      return;
    }

    if (req.method === "PUT") {
      const body = await readJson(req);
      const password = String(body.password || "").trim();
      const label = body.label !== undefined ? String(body.label || "").trim() : undefined;
      if (password && password.length < 4) {
        sendJson(res, 400, { error: "Mật khẩu tối thiểu 4 ký tự" });
        return;
      }
      if (!password && label === undefined) {
        sendJson(res, 400, { error: "Cần mật khẩu mới hoặc label" });
        return;
      }
      const current = items[idx];
      if (label !== undefined) current.label = label || "Khách";
      if (password) {
        const { salt, hash } = hashPassword(password);
        current.salt = salt;
        current.hash = hash;
      }
      current.updatedAt = new Date().toISOString();
      items[idx] = current;
      await savePasswords(items);
      sendJson(res, 200, { item: publicItem(current) });
      return;
    }

    if (req.method === "DELETE") {
      const next = items.filter((x) => String(x.id) !== String(id));
      await savePasswords(next);
      sendJson(res, 200, { ok: true });
      return;
    }

    sendJson(res, 405, { error: "Method not allowed" });
  } catch (err) {
    sendJson(res, 500, { error: err.message || "Lỗi API mật khẩu" });
  }
};
