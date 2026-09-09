const { isStoreConfigured } = require("../_lib/redis");
const {
  listPasswords,
  verifyPassword,
} = require("../_lib/passwords");
const { createSessionToken, readJson, sendJson } = require("../_lib/session");

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    sendJson(res, 405, { error: "Method not allowed" });
    return;
  }

  if (!isStoreConfigured()) {
    sendJson(res, 503, { error: "Chưa kết nối Redis/KV trên Vercel" });
    return;
  }

  let body;
  try {
    body = await readJson(req);
  } catch {
    sendJson(res, 400, { error: "JSON không hợp lệ" });
    return;
  }

  const password = String(body.password || "").trim();
  if (!password) {
    sendJson(res, 400, { error: "Nhập mật khẩu" });
    return;
  }

  try {
    const items = await listPasswords();
    if (!items.length) {
      sendJson(res, 403, { error: "Chưa có mật khẩu nào được cấp. Liên hệ admin." });
      return;
    }

    const matched = items.find((item) =>
      verifyPassword(password, item.salt, item.hash)
    );
    if (!matched) {
      sendJson(res, 401, { error: "Mật khẩu không đúng hoặc đã bị thu hồi" });
      return;
    }

    const token = createSessionToken(matched);
    sendJson(res, 200, {
      ok: true,
      token,
      label: matched.label || "",
    });
  } catch (err) {
    sendJson(res, 500, { error: err.message || "Lỗi xác thực" });
  }
};
