// hmac.js — ONE small swappable module for all HMAC handling.
// Convention:
//   signature = lowercase hex HMAC-SHA256(secret, rawBody)
//   header    = x-agent-games-signature, value is the hex digest,
//               an optional "sha256=" prefix is tolerated on verify,
//               a base64 digest is also tolerated on verify.
// Secret encoding — the platform shows the secret once as a 64-char hex
// string, but NEVER says which bytes are the HMAC key. Preflight proved
// (2026-11-15, two rotated secrets, both 401) that the platform does NOT
// sign with the hex-decoded 32 bytes. So verify tries EVERY plausible
// reading of the secret and remembers which one matched:
//   - "utf8"   : UTF-8 bytes of the secret string as given (the platform's
//                "conventional reading" — this is what preflight uses)
//   - "hex"    : the 32 raw bytes, when the secret is 64 hex chars
//   - "base64" : the 32 raw bytes, when base64 decoding yields 32 bytes
// Responses are signed with the SAME key reading that verified the
// request, so the platform can verify our signature with its own
// convention, whatever it is. If this convention fails preflight, change
// ONLY this file.
"use strict";
const crypto = require("node:crypto");

function candidateKeys() {
  const s = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!s) return [];
  const t = s.trim();
  const out = [];
  const seen = new Set();
  const add = (name, buf) => {
    const k = buf.toString("hex");
    if (!seen.has(k)) { seen.add(k); out.push({ name, key: buf }); }
  };
  // The platform's most likely reading: the secret string itself.
  add("utf8", Buffer.from(t, "utf8"));
  if (/^[0-9a-fA-F]{64}$/.test(t)) add("hex", Buffer.from(t, "hex"));
  try {
    const b = Buffer.from(t, "base64");
    if (b.length === 32) add("base64", b);
  } catch (_) { /* not base64 */ }
  return out;
}

function sign(rawBody, keyName) {
  const cands = candidateKeys();
  if (!cands.length) return null;
  const c = cands.find((x) => x.name === keyName) || cands[0];
  return crypto.createHmac("sha256", c.key).update(rawBody).digest("hex");
}

// Returns { status: "ok"|"missing-secret"|"missing-header"|"bad", key }
// where key is the name of the candidate key reading that matched
// ("utf8" | "hex" | "base64") or null.
function verify(rawBody, headerValue) {
  const cands = candidateKeys();
  if (!cands.length) return { status: "missing-secret", key: null };
  if (!headerValue) return { status: "missing-header", key: null };
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7);
  let got = null;
  if (/^[0-9a-fA-F]{64}$/.test(v)) {
    got = Buffer.from(v.toLowerCase(), "hex");
  } else {
    try { got = Buffer.from(v, "base64"); } catch (_) { return { status: "bad", key: null }; }
  }
  for (const c of cands) {
    const exp = crypto.createHmac("sha256", c.key).update(rawBody).digest();
    if (got.length === exp.length && crypto.timingSafeEqual(got, exp)) {
      return { status: "ok", key: c.name };
    }
  }
  return { status: "bad", key: null };
}

module.exports = { candidateKeys, sign, verify };
