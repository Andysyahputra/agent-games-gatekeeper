// Full test suite for the gatekeeper endpoint (runs against the local server
// over real HTTP). Usage: node test/run-tests.mjs [baseUrl]
// If baseUrl is given, tests run against that URL instead of a local server
// (the HMAC secret must then be set in env AGENT_GAMES_HMAC_SECRET — the
// test signs requests with it; for the deployed URL this means the REAL
// secret, which the tester supplies via env, never in this file).
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import * as snarkjs from "snarkjs";

const TEST_SECRET = "test-only-secret-for-local-testing";
const secret = process.env.AGENT_GAMES_HMAC_SECRET || TEST_SECRET;
const remote = process.argv[2] || null;
const PORT = 3456;
const BASE = remote || `http://127.0.0.1:${PORT}`;

const VK = JSON.parse(fs.readFileSync("./circuits/vk.json", "utf8"));
const VKHASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xE8BF9bb3A4A63385B6c1e0e4F44AE23c883c16C3";
const OTHER = "0x000000000000000000000000000000000000dEaD";

function sign(body) {
  return crypto.createHmac("sha256", Buffer.from(secret, "utf8")).update(body).digest("hex");
}

let localProc = null;
async function startLocal() {
  localProc = spawn("node", ["server.js"], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: TEST_SECRET },
    stdio: "ignore",
  });
  for (let i = 0; i < 30; i++) {
    try {
      const r = await fetch(`${BASE}/`);
      if (r.ok) return;
    } catch (_) { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("local server did not start");
}

function task(overrides = {}, inputOverrides = {}) {
  return {
    task_id: "task-valid-001",
    type: "agent-games.proof-gatekeeper.v1",
    mode: "competition",
    issued_at: "2026-11-15T07:00:00Z",
    deadline_at: "2026-11-15T07:01:00Z",
    input: {
      registered_vk: VKHASH,
      proof_vk: VKHASH,
      minimum: "100",
      public_balance: "500",
      expiry_block: "20000000",
      current_block: "19999999",
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: "10",
      max_transfer: "100",
      proof_tx: "0xaaaabbbbccccdddd000000000000000000000000000000000000000000000001",
      ...inputOverrides,
    },
    ...overrides,
  };
}

const results = [];
async function post(t, { badSig = false, noSig = false } = {}) {
  const body = JSON.stringify(t);
  const headers = { "Content-Type": "application/json" };
  if (!noSig) headers["x-agent-games-signature"] = badSig ? "0".repeat(64) : sign(Buffer.from(body));
  const t0 = Date.now();
  const res = await fetch(BASE + "/", { method: "POST", headers, body });
  const text = await res.text();
  return { status: res.status, text, ms: Date.now() - t0, respSig: res.headers.get("x-agent-games-signature") };
}

async function verifyProofInResponse(body, label) {
  const j = JSON.parse(body);
  if (!j.proof || !j.publicSignals) return { present: false };
  const ok = await snarkjs.groth16.verify(VK, j.publicSignals, j.proof);
  const bytes = Buffer.byteLength(JSON.stringify(j.proof));
  return { present: true, ok, bytes, nSignals: j.publicSignals.length };
}

async function check(name, t, expect, opts = {}) {
  const r = await post(t, opts);
  let pass = true;
  const notes = [];
  if (r.status !== (expect.status ?? 200)) { pass = false; notes.push(`status ${r.status} != ${expect.status ?? 200}`); }
  let j = null;
  try { j = JSON.parse(r.text); } catch (_) { pass = false; notes.push("response not JSON"); }
  if (j && expect.decision && j.decision !== expect.decision) { pass = false; notes.push(`decision ${j.decision} != ${expect.decision}`); }
  if (j && expect.reason && j.reason_code !== expect.reason) { pass = false; notes.push(`reason ${j.reason_code} != ${expect.reason}`); }
  if (j && expect.proofTx !== undefined && j.proof_tx !== expect.proofTx) { pass = false; notes.push(`proof_tx mismatch`); }
  // Response signature must verify (when a signature is expected).
  if (r.status === 200 && r.respSig) {
    const good = crypto.timingSafeEqual(Buffer.from(r.respSig, "hex"), Buffer.from(sign(Buffer.from(r.text)), "hex"));
    if (!good) { pass = false; notes.push("response signature BAD"); }
  } else if (r.status === 200 && !r.respSig) { pass = false; notes.push("response signature MISSING"); }
  // Proof verification (when a proof is due).
  let pv = null;
  if (j && expect.proof === true) {
    pv = await verifyProofInResponse(r.text, name);
    if (!pv.present) { pass = false; notes.push("proof MISSING"); }
    else if (!pv.ok) { pass = false; notes.push("proof DOES NOT VERIFY"); }
  }
  if (j && expect.proof === false) {
    if (j.proof !== null) { pass = false; notes.push("proof should be null"); }
  }
  results.push({ name, pass, ms: r.ms, notes, proofBytes: pv?.bytes ?? null });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}  (${r.ms} ms)${notes.length ? " — " + notes.join("; ") : ""}${pv?.present ? ` [proof ${pv.bytes}B verify=${pv.ok}]` : ""}`);
  return { r, j };
}

async function main() {
  if (!remote) await startLocal();
  console.log(`Testing ${BASE} (secret: ${remote ? "from env" : "TEST-ONLY local secret"})`);
  console.log("---");

  // 1. Valid case (fresh proof_tx).
  const valid = task();
  const { r: validRes } = await check("valid APPROVE", valid, { decision: "APPROVE", reason: "VALID_CONDITION", proof: true, proofTx: valid.input.proof_tx });

  // 2. Replay of the same task_id -> byte-identical cached response.
  const replay = await post(valid);
  const identical = replay.text === validRes.text && replay.status === 200;
  results.push({ name: "replay task_id identical", pass: identical, ms: replay.ms, notes: identical ? [] : ["body differs from first response"] });
  console.log(`${identical ? "PASS" : "FAIL"}  replay task_id identical  (${replay.ms} ms)`);

  // 3. Bad HMAC -> 401 before parsing.
  const bad = await post(valid, { badSig: true });
  const badPass = bad.status === 401;
  results.push({ name: "bad HMAC -> 401", pass: badPass, ms: bad.ms, notes: badPass ? [] : [`status ${bad.status}`] });
  console.log(`${badPass ? "PASS" : "FAIL"}  bad HMAC -> 401  (${bad.ms} ms)`);

  // 4. Missing HMAC -> 401.
  const no = await post(valid, { noSig: true });
  const noPass = no.status === 401;
  results.push({ name: "missing HMAC -> 401", pass: noPass, ms: no.ms, notes: noPass ? [] : [`status ${no.status}`] });
  console.log(`${noPass ? "PASS" : "FAIL"}  missing HMAC -> 401  (${no.ms} ms)`);

  // 5-10. The six traps (each with its own fresh proof_tx).
  const traps = [
    ["VK_SUBSTITUTION", { proof_vk: "0x1111111111111111111111111111111111111111111111111111111111111111" }, "0x1000000000000000000000000000000000000000000000000000000000000001"],
    ["THRESHOLD_MISMATCH", { public_balance: "50" }, "0x2000000000000000000000000000000000000000000000000000000000000002"],
    ["PROOF_REUSED", { proof_tx: valid.input.proof_tx }, valid.input.proof_tx], // same proof_tx, NEW task_id
    ["EXPIRED_CONDITION", { current_block: "20000001" }, "0x3000000000000000000000000000000000000000000000000000000000000003"],
    ["RECIPIENT_MISMATCH", { recipient: OTHER }, "0x4000000000000000000000000000000000000000000000000000000000000004"],
    ["AMOUNT_OVERFLOW", { amount: "101" }, "0x5000000000000000000000000000000000000000000000000000000000000005"],
  ];
  for (const [reason, patch, ptx] of traps) {
    const t = task({ task_id: `task-trap-${reason.toLowerCase()}` }, { ...patch, proof_tx: ptx });
    // PROOF_REUSED with all five checks passing cannot produce a decision-0
    // proof, so proof must be null; the other rejects prove with decision 0.
    const proofExpected = reason !== "PROOF_REUSED";
    await check(`trap ${reason}`, t, { decision: "REJECT", reason, proof: proofExpected });
  }

  // 11. String task_id (non-numeric) still proves (sha256 mod p mapping).
  const strTask = task({ task_id: "task-abc-123-xyz" }, { proof_tx: "0x9999888877776666000000000000000000000000000000000000000000000002" });
  await check("string task_id APPROVE", strTask, { decision: "APPROVE", reason: "VALID_CONDITION", proof: true });

  // 12. GET health check.
  const t0 = Date.now();
  const health = await fetch(BASE + "/");
  const healthPass = health.status === 200;
  results.push({ name: "GET health 200", pass: healthPass, ms: Date.now() - t0, notes: [] });
  console.log(`${healthPass ? "PASS" : "FAIL"}  GET health 200`);

  console.log("---");
  const passed = results.filter((r) => r.pass).length;
  console.log(`TOTAL: ${passed}/${results.length} passed`);
  const lat = results.filter((r) => r.ms != null).map((r) => r.ms);
  console.log(`latency ms: min ${Math.min(...lat)}, max ${Math.max(...lat)}, median ${lat.sort((a, b) => a - b)[Math.floor(lat.length / 2)]}`);
  if (localProc) localProc.kill();
  process.exit(passed === results.length ? 0 : 1);
}

main().catch((e) => { console.error("TEST RUN FAILED:", e); if (localProc) localProc.kill(); process.exit(2); });
