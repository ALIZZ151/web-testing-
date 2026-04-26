const {
  isAuthConfigured,
  json,
  methodNotAllowed,
  readJsonBody,
  verifyPassword,
  createSessionCookie
} = require("../lib/auth");
const {
  getClientIp,
  checkRateLimit,
  recordFailure,
  clearFailures
} = require("../lib/rateLimit");

const GENERIC_LOGIN_ERROR = "Login gagal. Cek username atau password.";

module.exports = async function handler(req, res) {
  if (req.method !== "POST") return methodNotAllowed(res, ["POST"]);

  const identifier = getClientIp(req);
  const rateLimit = checkRateLimit(identifier);

  if (rateLimit.limited) {
    res.setHeader("Retry-After", String(rateLimit.retryAfterSeconds));
    return json(res, 429, { ok: false, message: GENERIC_LOGIN_ERROR });
  }

  if (!isAuthConfigured()) {
    return json(res, 503, {
      ok: false,
      message: "Login admin belum dikonfigurasi."
    });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (error) {
    recordFailure(identifier);
    return json(res, 400, { ok: false, message: GENERIC_LOGIN_ERROR });
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  const usernameMatches = username === process.env.ADMIN_USERNAME;
  const passwordMatches = verifyPassword(password, process.env.ADMIN_PASSWORD_HASH);

  if (!usernameMatches || !passwordMatches) {
    recordFailure(identifier);
    return json(res, 401, { ok: false, message: GENERIC_LOGIN_ERROR });
  }

  clearFailures(identifier);
  res.setHeader("Set-Cookie", createSessionCookie(req, username));
  return json(res, 200, { ok: true });
};
