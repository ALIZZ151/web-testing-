const WINDOW_MS = 10 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const MAX_FAILED_ATTEMPTS = 5;

const attempts = new Map();

function now() {
  return Date.now();
}

function getClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];
  if (typeof forwardedFor === "string" && forwardedFor.trim()) {
    return forwardedFor.split(",")[0].trim();
  }

  return req.headers["x-real-ip"] || req.socket?.remoteAddress || "unknown";
}

function cleanup(identifier) {
  const entry = attempts.get(identifier);
  if (!entry) return null;

  const currentTime = now();
  if (entry.lockedUntil && entry.lockedUntil > currentTime) return entry;
  if (entry.firstAttemptAt + WINDOW_MS > currentTime) return entry;

  attempts.delete(identifier);
  return null;
}

function checkRateLimit(identifier) {
  const entry = cleanup(identifier);
  if (!entry) return { limited: false, retryAfterSeconds: 0 };

  if (entry.lockedUntil && entry.lockedUntil > now()) {
    return {
      limited: true,
      retryAfterSeconds: Math.ceil((entry.lockedUntil - now()) / 1000)
    };
  }

  return { limited: false, retryAfterSeconds: 0 };
}

function recordFailure(identifier) {
  const currentTime = now();
  const entry = cleanup(identifier) || {
    count: 0,
    firstAttemptAt: currentTime,
    lockedUntil: 0
  };

  entry.count += 1;

  if (entry.count >= MAX_FAILED_ATTEMPTS) {
    entry.lockedUntil = currentTime + LOCK_MS;
  }

  attempts.set(identifier, entry);
  return checkRateLimit(identifier);
}

function clearFailures(identifier) {
  attempts.delete(identifier);
}

module.exports = {
  getClientIp,
  checkRateLimit,
  recordFailure,
  clearFailures,
  WINDOW_MS,
  LOCK_MS,
  MAX_FAILED_ATTEMPTS
};
