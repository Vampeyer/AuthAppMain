// fail2ban.js — Simple IP-based rate limiter for failed logins
const failedAttempts = new Map(); // IP -> {count: number, lastAttempt: timestamp, banUntil: timestamp or null}
const BAN_DURATION = 5 * 60 * 1000; // 5 minutes ban
const ATTEMPT_WINDOW = 2 * 60 * 1000; // 2 minutes window for attempts
const MAX_ATTEMPTS = 3; // Max failed attempts in window

function checkRateLimit(ip) {
  const now = Date.now();
  let record = failedAttempts.get(ip) || { count: 0, lastAttempt: 0, banUntil: null };

  // If banned, return remaining time
  if (record.banUntil && now < record.banUntil) {
    console.log('%cFAIL2BAN: IP banned until', 'color:orange', new Date(record.banUntil), 'IP:', ip);
    return { banned: true, remaining: Math.ceil((record.banUntil - now) / 1000) };
  }

  // Reset count if outside window
  if (now - record.lastAttempt > ATTEMPT_WINDOW) {
    record.count = 0;
  }

  failedAttempts.set(ip, record);
  return { banned: false };
}

function recordFailure(ip) {
  const now = Date.now();
  let record = failedAttempts.get(ip) || { count: 0, lastAttempt: 0, banUntil: null };

  record.count += 1;
  record.lastAttempt = now;

  if (record.count >= MAX_ATTEMPTS) {
    record.banUntil = now + BAN_DURATION;
    console.log('%cFAIL2BAN: IP banned for', 'color:red', (BAN_DURATION / 60000), 'minutes. IP:', ip, 'Ban until:', new Date(record.banUntil));
  } else {
    console.log('%cFAIL2BAN: Failed attempt recorded. Count:', 'color:yellow', record.count, 'IP:', ip);
  }

  failedAttempts.set(ip, record);
}

function clearAttempts(ip) {
  if (failedAttempts.has(ip)) {
    failedAttempts.delete(ip);
    console.log('%cFAIL2BAN: Attempts cleared for IP:', 'color:green', ip);
  }
}

module.exports = { checkRateLimit, recordFailure, clearAttempts };