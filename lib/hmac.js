// hmac.js — ONE small swappable module for all HMAC handling.
// Convention (the "conventional reading" of the Agent Games build guide):
//   signature = lowercase hex HMAC-SHA256(secret, rawBody)
//   header    = x-agent-games-signature, value is the hex digest,
//               an optional "sha256=" prefix is tolerated on verify.
// Secret encoding (ambiguous at registration — the secret is shown once as a
// 32-byte random value; it may be presented as hex, base64, or raw text):
//   - 64 hex chars            -> the 32 raw bytes
//   - base64 decoding to 32B  -> the 32 raw bytes
//   - anything else           -> UTF-8 bytes of the string as given
// If this convention fails preflight, change ONLY this file.
"use strict";
const crypto = require("node:crypto");

function secretBytes() {
  const s = process.env.AGENT_GAMES_HMAC_SECRET;
  if (!s) return null;
  const t = s.trim();
  if (/^[0-9a-fA-F]{64}$/.test(t)) return Buffer.from(t, "hex");
  try {
    const b = Buffer.from(t, "base64");
    if (b.length === 32) return b;
  } catch (_) { /* fall through */ }
  return Buffer.from(t, "utf8");
}

function sign(rawBody) {
  const key = secretBytes();
  if (!key) return null;
  return crypto.createHmac("sha256", key).update(rawBody).digest("hex");
}

// Returns: "ok" | "missing-secret" | "missing-header" | "bad"
function verify(rawBody, headerValue) {
  const key = secretBytes();
  if (!key) return "missing-secret";
  if (!headerValue) return "missing-header";
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7);
  const expectedHex = crypto.createHmac("sha256", key).update(rawBody).digest("hex");
  let got;
  if (/^[0-9a-fA-F]{64}$/.test(v)) {
    got = Buffer.from(v.toLowerCase(), "hex");
  } else {
    try { got = Buffer.from(v, "base64"); } catch (_) { return "bad"; }
  }
  const exp = Buffer.from(expectedHex, "hex");
  if (got.length !== exp.length) return "bad";
  return crypto.timingSafeEqual(got, exp) ? "ok" : "bad";
}

module.exports = { secretBytes, sign, verify };
