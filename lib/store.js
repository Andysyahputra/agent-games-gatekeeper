// store.js — persistent seen-set of proof_tx + idempotency cache of responses.
// In-memory (fast path) + file-backed JSON (survives restarts on one machine).
// LIMITATION (documented honestly): Vercel serverless is stateless. Each
// instance keeps its own in-memory set and its own /tmp file; instances do
// NOT share state, and /tmp is discarded when an instance is recycled. So
// cross-instance PROOF_REUSED detection is best-effort only on Vercel: a
// replay landing on a different warm instance may not be recognised as
// reused. A durable cross-instance store (Vercel KV / Upstash Redis /
// Postgres) is the fix if the platform replays across instances — it needs
// no secret, but it is NOT set up here. Locally (node server.js) the file
// at ./data/seen.json IS durable across restarts.
"use strict";
const fs = require("node:fs");
const path = require("node:path");

function storePath() {
  if (process.env.SEEN_SET_PATH) return process.env.SEEN_SET_PATH;
  if (process.env.VERCEL) return path.join("/tmp", "gatekeeper-seen.json");
  return path.join(__dirname, "..", "data", "seen.json");
}

let seen = new Set();       // proof_tx strings
let responses = new Map();  // task_id -> exact response body string
let loaded = false;

function load() {
  if (loaded) return;
  loaded = true;
  try {
    const raw = fs.readFileSync(storePath(), "utf8");
    const data = JSON.parse(raw);
    if (Array.isArray(data.seen)) seen = new Set(data.seen);
    if (data.responses && typeof data.responses === "object") {
      responses = new Map(Object.entries(data.responses));
    }
  } catch (_) { /* first run / no file yet — start empty */ }
}

function save() {
  try {
    const p = storePath();
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const tmp = p + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify({ seen: [...seen], responses: Object.fromEntries(responses) }));
    fs.renameSync(tmp, p);
  } catch (_) { /* persistence is best-effort; never fail a request over it */ }
}

function hasSeenProofTx(proofTx) {
  load();
  return proofTx ? seen.has(proofTx) : false;
}

function markSeenProofTx(proofTx) {
  if (!proofTx) return;
  load();
  if (!seen.has(proofTx)) { seen.add(proofTx); save(); }
}

function cachedResponse(taskId) {
  load();
  return responses.get(taskId) || null;
}

function cacheResponse(taskId, body) {
  load();
  responses.set(taskId, body);
  save();
}

function stats() {
  load();
  return { seenProofTx: seen.size, cachedResponses: responses.size, path: storePath() };
}

module.exports = { hasSeenProofTx, markSeenProofTx, cachedResponse, cacheResponse, stats };
