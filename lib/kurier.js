// kurier.js — submit a Groth16 proof via Kurier (zkVerify REST relay).
// Docs: https://docs.zkverify.io/overview/getting-started/kurier
//   Mainnet API: https://api.kurier.xyz/api/v1   (testnet: api-testnet.kurier.xyz)
//   POST /register-vk/{API_KEY}   — register vk once (the Agent Games
//     gatekeeper vk is ALREADY registered on zkVerify mainnet by the platform,
//     vkHash 0x6b79c6...d77b0, so this endpoint sends vkRegistered: true
//     and does NOT call register-vk).
//   POST /submit-proof/{API_KEY} — { proofType: "groth16",
//     vkRegistered: true, proofOptions: { library: "snarkjs", curve: "bn254" },
//     proofData: { proof, publicSignals, vk: vkHash } }
//     (+ chainId only if KURIER_CHAIN_ID is set — it selects the aggregation
//     destination chain; unset means no aggregation target.)
//   GET  /job-status/{API_KEY}/{jobId}
//     statuses: Queued -> Valid -> Submitted -> IncludedInBlock -> Finalized.
// The task's rule: return the tx hash as soon as it exists at the Submitted
// stage (~4 s) — do NOT wait for finalization (~27 s). This module polls
// job-status at 1 s intervals with a hard deadline (default 5 s, env
// KURIER_POLL_MS) and returns whatever tx hash it has seen by then.
// Returns null when no KURIER_API_KEY is configured (caller then returns the
// proof in the response and proof_tx = the task's proof_tx).
// NOTE: the tx-hash field name in job-status responses is not documented in
// the public docs; this code checks txHash / transactionHash / extrinsicHash
// / hash in that order. Live behaviour is UNTESTED (no key yet) — verify at
// preflight after registration and adjust here if the field differs.
"use strict";

const API_URL = (process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1").replace(/\/$/, "");
const POLL_MS = Number(process.env.KURIER_POLL_MS || 5000);
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function postJson(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* keep raw text */ }
  if (!res.ok) throw new Error(`Kurier POST ${res.status}: ${text.slice(0, 300)}`);
  return json ?? { raw: text };
}

async function getJson(url) {
  const res = await fetch(url, { method: "GET" });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* keep raw text */ }
  if (!res.ok) throw new Error(`Kurier GET ${res.status}: ${text.slice(0, 300)}`);
  return json ?? { raw: text };
}

function extractTxHash(job) {
  if (!job || typeof job !== "object") return null;
  for (const k of ["txHash", "transactionHash", "extrinsicHash", "hash", "tx_hash"]) {
    if (typeof job[k] === "string" && job[k]) return job[k];
  }
  if (job.data && typeof job.data === "object") return extractTxHash(job.data);
  return null;
}

// Submit proof; resolve as soon as the job reaches Submitted (or further)
// with a tx hash, or when POLL_MS elapses. Never throws — returns a result
// object the caller can attach to the response.
async function submitProof(proof, publicSignals) {
  const apiKey = process.env.KURIER_API_KEY;
  if (!apiKey) return { attempted: false, reason: "no KURIER_API_KEY configured" };
  const started = Date.now();
  try {
    const params = {
      proofType: "groth16",
      vkRegistered: true,
      proofOptions: { library: "snarkjs", curve: "bn254" },
      proofData: { proof, publicSignals, vk: VK_HASH },
    };
    if (process.env.KURIER_CHAIN_ID) params.chainId = Number(process.env.KURIER_CHAIN_ID);
    const submitted = await postJson(`${API_URL}/submit-proof/${apiKey}`, params);
    const jobId = submitted.jobId || submitted.job_id || (submitted.data && submitted.data.jobId) || null;
    if (!jobId) return { attempted: true, jobId: null, status: "unknown", txHash: null, note: "submit-proof returned no jobId", raw: submitted };
    // Poll until Submitted (tx hash exists) or deadline.
    let status = submitted.status || "Queued";
    let txHash = extractTxHash(submitted);
    while (Date.now() - started < POLL_MS) {
      if (["Submitted", "IncludedInBlock", "Finalized"].includes(status) && txHash) break;
      if (status === "Failed") break;
      await sleep(1000);
      if (Date.now() - started >= POLL_MS) break;
      const job = await getJson(`${API_URL}/job-status/${apiKey}/${jobId}`);
      status = job.status || (job.data && job.data.status) || status;
      txHash = extractTxHash(job) || txHash;
    }
    return { attempted: true, jobId, status, txHash, ms: Date.now() - started };
  } catch (e) {
    return { attempted: true, jobId: null, status: "error", txHash: null, error: String(e).slice(0, 300), ms: Date.now() - started };
  }
}

module.exports = { submitProof, API_URL, POLL_MS };
