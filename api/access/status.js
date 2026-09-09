const { isStoreConfigured } = require("../_lib/redis");
const { listPasswords } = require("../_lib/passwords");
const { sendJson } = require("../_lib/session");

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    sendJson(res, 405, { error: "Method not allowed" });
    return;
  }

  const configured = isStoreConfigured();
  if (!configured) {
    sendJson(res, 200, {
      configured: false,
      gate: false,
      count: 0,
      message: "Chưa kết nối Redis/KV — trang khách tạm mở.",
    });
    return;
  }

  try {
    const items = await listPasswords();
    const count = items.length;
    sendJson(res, 200, {
      configured: true,
      gate: true,
      count,
      message:
        count > 0
          ? "Cần mật khẩu hợp lệ để vào web."
          : "Chưa có mật khẩu — tạo trong Admin rồi gửi khách.",
    });
  } catch (err) {
    sendJson(res, 500, { error: err.message || "Lỗi đọc kho mật khẩu" });
  }
};
