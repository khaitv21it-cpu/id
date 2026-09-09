const { isStoreConfigured } = require("../_lib/redis");
const { listPasswords } = require("../_lib/passwords");
const { parseSessionToken, sendJson } = require("../_lib/session");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    sendJson(res, 405, { error: "Method not allowed" });
    return;
  }

  if (!isStoreConfigured()) {
    sendJson(res, 200, { ok: true, gate: false, reason: "unconfigured" });
    return;
  }

  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  const parsed = parseSessionToken(token);
  if (!parsed) {
    sendJson(res, 401, { ok: false, error: "Phiên không hợp lệ hoặc đã hết hạn" });
    return;
  }

  try {
    const items = await listPasswords();
    if (!items.length) {
      sendJson(res, 401, { ok: false, error: "Không còn mật khẩu hợp lệ" });
      return;
    }
    const item = items.find((x) => x.id === parsed.id);
    if (!item) {
      sendJson(res, 401, { ok: false, error: "Mật khẩu đã bị xóa" });
      return;
    }
    if (String(item.updatedAt) !== String(parsed.updatedAt)) {
      sendJson(res, 401, { ok: false, error: "Mật khẩu đã đổi — nhập lại" });
      return;
    }
    sendJson(res, 200, { ok: true, gate: true, label: item.label || "" });
  } catch (err) {
    sendJson(res, 500, { error: err.message || "Lỗi kiểm tra phiên" });
  }
};
