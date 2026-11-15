// Targeted test for the preflight 401 fix (2026-11-15): the platform shows
// the HMAC secret once as a 64-char hex string and signs with the UTF-8
// bytes OF THAT STRING, while the endpoint used to hex-decode it to 32
// bytes — every preflight request failed 401. This test starts the server
// with a 64-hex-char secret and proves BOTH key readings are accepted,
// and that responses are signed with the same reading that verified the
// request (so the platform can verify our signature too).
// Usage: node test/hmac-conventions.mjs
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import * as snarkjs from "snarkjs";

const HEX_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
const PORT = 3457;
const BASE = `http://127.0.0.1:${PORT}`;
const VK = JSON.parse(fs.readFileSync("./circuits/vk.json", "utf8"));
const VKHASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xE8BF9bb3A4A63385B6c1e0e4F44AE23c883c16C3";

function signWith(body, keyBuf) {
  return crypto.createHmac("sha256", keyBuf).update(body).digest("hex");
}
const signUtf8 = (b) => signWith(b, Buffer.from(HEX_SECRET, "utf8"));
const signHex = (b) => signWith(b, Buffer.from(HEX_SECRET, "hex"));

let proc = null;
async function start() {
  proc = spawn("node", ["server.js"], {
    cwd: process.cwd(),
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: HEX_SECRET },
    stdio: "ignore",
  });
  for (let i = 0; i < 30; i++) {
    try { const r = await fetch(`${BASE}/`); if (r.ok) return; } catch (_) { /* not up */ }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("server did not start");
}

function task(id, ptx) {
  return {
    task_id: id, type: "agent-games.proof-gatekeeper.v1", mode: "competition",
    issued_at: "2026-11-15T07:00:00Z", deadline_at: "2026-11-15T07:01:00Z",
    input: {
      registered_vk: VKHASH, proof_vk: VKHASH, minimum: "100", public_balance: "500",
      expiry_block: "20000000", current_block: "19999999",
      recipient: ADDR, condition_recipient: ADDR, amount: "10", max_transfer: "100",
      proof_tx: ptx,
    },
  };
}

const results = [];
async function post(t, signer, label) {
  const body = JSON.stringify(t);
  const headers = { "Content-Type": "application/json", "x-agent-games-signature": signer(Buffer.from(body)) };
  const res = await fetch(BASE + "/", { method: "POST", headers, body });
  const text = await res.text();
  return { status: res.status, text, respSig: res.headers.get("x-agent-games-signature"), label };
}

async function checkSigned(name, t, signer, expectStatus) {
  const r = await post(t, signer, name);
  let pass = r.status === expectStatus;
  const notes = [];
  if (!pass) notes.push(`status ${r.status} != ${expectStatus}`);
  if (r.status === 200) {
    // Response signature must verify under the SAME key reading used to sign the request.
    const good = crypto.timingSafeEqual(Buffer.from(r.respSig, "hex"), Buffer.from(signer(Buffer.from(r.text)), "hex"));
    if (!good) { pass = false; notes.push("response signature BAD under request key reading"); }
    try {
      const j = JSON.parse(r.text);
      if (j.decision !== "APPROVE") { pass = false; notes.push(`decision ${j.decision}`); }
      if (j.proof && j.publicSignals) {
        const ok = await snarkjs.groth16.verify(VK, j.publicSignals, j.proof);
        if (!ok) { pass = false; notes.push("proof DOES NOT VERIFY"); }
      } else { pass = false; notes.push("proof MISSING"); }
    } catch (_) { pass = false; notes.push("response not JSON"); }
  }
  results.push({ name, pass, notes });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${notes.length ? " — " + notes.join("; ") : ""}`);
}

async function main() {
  await start();
  console.log(`Testing ${BASE} with 64-hex-char secret`);
  console.log("---");
  // 1. Platform convention: sign with UTF-8 bytes of the hex string.
  await checkSigned(
    "hex secret, UTF-8 key reading (platform convention) -> 200",
    task("task-hex-utf8", "0x1111111111111111111111111111111111111111111111111111111111111111"),
    signUtf8, 200,
  );
  // 2. Old convention still accepted: sign with hex-decoded bytes.
  await checkSigned(
    "hex secret, hex-decoded key reading (old) -> 200",
    task("task-hex-decoded", "0x2222222222222222222222222222222222222222222222222222222222222222"),
    signHex, 200,
  );
  // 3. Bad signature -> 401.
  const bad = await post(task("task-bad", "0x3333333333333333333333333333333333333333333333333333333333333333"), () => "0".repeat(64), "bad sig");
  const badPass = bad.status === 401;
  results.push({ name: "bad signature -> 401", pass: badPass, notes: badPass ? [] : [`status ${bad.status}`] });
  console.log(`${badPass ? "PASS" : "FAIL"}  bad signature -> 401`);
  // 4. GET health -> 200.
  const h = await fetch(BASE + "/");
  const hPass = h.status === 200;
  results.push({ name: "GET health 200", pass: hPass, notes: [] });
  console.log(`${hPass ? "PASS" : "FAIL"}  GET health 200`);
  console.log("---");
  const passed = results.filter((r) => r.pass).length;
  console.log(`TOTAL: ${passed}/${results.length} passed`);
  if (proc) proc.kill();
  process.exit(passed === results.length ? 0 : 1);
}
main().catch((e) => { console.error("TEST RUN FAILED:", e); if (proc) proc.kill(); process.exit(2); });
