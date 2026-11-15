// handler.js — core Proof Gatekeeper logic, framework-free.
// Used by both the local server (server.js) and the Vercel function.
// Flow (in order):
//   1. HMAC-verify x-agent-games-signature over the RAW body, BEFORE parsing.
//      Bad/missing -> 401. No secret configured -> 503 (fail closed).
//   2. Parse JSON. Malformed -> 400.
//   3. Idempotency: redelivered task_id -> byte-identical cached response.
//   4. Trap checks (deterministic, evaluated in the documented order; first
//      failing trap is the reason_code):
//        VK_SUBSTITUTION   proof_vk != registered_vk
//        THRESHOLD_MISMATCH public_balance < minimum
//        PROOF_REUSED      proof_tx already in the seen-set
//        EXPIRED_CONDITION current_block > expiry_block
//        RECIPIENT_MISMATCH recipient != condition_recipient
//        AMOUNT_OVERFLOW   amount > max_transfer
//        VALID_CONDITION   all pass -> APPROVE
//   5. Groth16 proof with decision = AND of the five circuit checks.
//      A wrong decision cannot produce a witness (fullProve throws) — that
//      is correct: return the decision WITHOUT a proof (fail closed, never
//      approve on error). PROOF_REUSED with all five checks passing is the
//      normal no-proof case (the platform excludes these from the proof bonus).
//   6. Kurier submission (only when KURIER_API_KEY is set): submit, return
//      the tx hash as soon as the job reaches Submitted; never wait for
//      finalization. Without a key, proof_tx echoes the task's proof_tx.
//   7. Sign the raw response body with x-agent-games-signature.
// Response: { decision, reason_code, proof_tx, proof, publicSignals }
//   (+ kurier_job_id / kurier_status only when a Kurier submission was
//   attempted). proof is null when no proof could be produced.
"use strict";
const hmac = require("./hmac");
const circuit = require("./circuit");
const kurier = require("./kurier");
const store = require("./store");

const HEADER = "x-agent-games-signature";

function jsonResponse(status, obj, signBody, keyName) {
  const body = JSON.stringify(obj);
  const headers = { "Content-Type": "application/json" };
  if (signBody) {
    const sig = hmac.sign(Buffer.from(body, "utf8"), keyName);
    if (sig) headers[HEADER] = sig;
  }
  return { status, headers, body };
}

function big(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(Math.trunc(v));
  const t = String(v).trim();
  return t.startsWith("0x") || t.startsWith("0X") ? BigInt(t) : BigInt(t);
}

// Returns { decision: "APPROVE"|"REJECT", reason_code } — first failing trap.
function evaluate(task) {
  const input = task.input;
  if (big(input.proof_vk) !== big(input.registered_vk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  }
  if (big(input.public_balance) < big(input.minimum)) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  }
  const proofTx = task.input.proof_tx || "";
  if (proofTx && store.hasSeenProofTx(proofTx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  }
  if (big(input.current_block) > big(input.expiry_block)) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  }
  if (big(input.recipient) !== big(input.condition_recipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  }
  if (big(input.amount) > big(input.max_transfer)) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

async function handlePost(rawBody, headers) {
  const t0 = Date.now();
  // 1. HMAC BEFORE parsing.
  const v = hmac.verify(rawBody, headers[HEADER] || headers["X-Agent-Games-Signature"]);
  if (v.status === "missing-secret") {
    return jsonResponse(503, { error: "hmac_secret_not_configured", hint: "set AGENT_GAMES_HMAC_SECRET" }, false);
  }
  if (v.status !== "ok") {
    return jsonResponse(401, { error: "invalid_signature" }, false);
  }
  // Sign every response with the SAME key reading that verified the
  // request, so the platform can verify our signature with its own
  // convention, whatever it is.
  const keyName = v.key;
  // 2. Parse.
  let task;
  try {
    task = JSON.parse(rawBody.toString("utf8"));
  } catch (_) {
    return jsonResponse(400, { error: "invalid_json" }, true, keyName);
  }
  if (!task || typeof task !== "object" || !task.task_id || !task.input || typeof task.input !== "object") {
    return jsonResponse(400, { error: "invalid_task_envelope", hint: "need task_id + input{}" }, true, keyName);
  }
  // 3. Idempotency — byte-identical cached response.
  const cached = store.cachedResponse(String(task.task_id));
  if (cached !== null) {
    const sig = hmac.sign(Buffer.from(cached, "utf8"), keyName);
    return { status: 200, headers: { "Content-Type": "application/json", ...(sig ? { [HEADER]: sig } : {}) }, body: cached, replay: true, ms: Date.now() - t0 };
  }
  // 4. Trap checks.
  let verdict;
  try {
    verdict = evaluate(task);
  } catch (e) {
    return jsonResponse(400, { error: "invalid_task_fields", detail: String(e).slice(0, 200) }, true, keyName);
  }
  const approve = verdict.decision === "APPROVE";
  // 5. Proof (best-effort; a wrong decision cannot prove — return w/o proof).
  let proof = null, publicSignals = null, proofMs = null, proofError = null;
  try {
    const r = await circuit.generateProof(task, approve);
    proof = r.proof; publicSignals = r.publicSignals; proofMs = r.ms;
  } catch (e) {
    proofError = String(e).slice(0, 200);
  }
  // Record the proof_tx as seen AFTER decisioning (so this task never flags
  // itself), whatever the outcome — a replay with a new task_id is a reuse.
  store.markSeenProofTx(task.input.proof_tx || "");
  // 6. Kurier (only with a key, only when we have a proof to submit).
  let proofTxOut = task.input.proof_tx || "";
  let kurierInfo = null;
  if (proof && process.env.KURIER_API_KEY) {
    const k = await kurier.submitProof(proof, publicSignals);
    if (k.attempted) {
      kurierInfo = { kurier_job_id: k.jobId || undefined, kurier_status: k.status, kurier_ms: k.ms };
      if (k.txHash) proofTxOut = k.txHash;
      if (k.error) kurierInfo.kurier_error = k.error;
    }
  }
  const response = {
    decision: verdict.decision,
    reason_code: verdict.reason_code,
    proof_tx: proofTxOut,
    proof,
    publicSignals,
    server_ms: Date.now() - t0,
    proof_ms: proofMs,
    ...(kurierInfo || {}),
  };
  const out = jsonResponse(200, response, true, keyName);
  store.cacheResponse(String(task.task_id), out.body);
  return { ...out, ms: Date.now() - t0, proofMs, proofError };
}

async function handleRequest(method, rawBody, headers) {
  if (method === "GET") {
    return jsonResponse(200, { status: "ok", service: "agent-games-gatekeeper", process_uptime_s: Math.round(process.uptime()), ...store.stats() }, false);
  }
  if (method !== "POST") {
    return jsonResponse(405, { error: "method_not_allowed" }, false);
  }
  return handlePost(rawBody || Buffer.alloc(0), headers || {});
}

module.exports = { handleRequest, evaluate, HEADER };
