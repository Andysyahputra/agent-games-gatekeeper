// Latency probe: N fresh APPROVE POSTs against a URL, prints per-request ms.
// Usage: AGENT_GAMES_HMAC_SECRET=<secret> node test/latency-probe.mjs <url> <n>
import crypto from "node:crypto";

const secret = process.env.AGENT_GAMES_HMAC_SECRET;
if (!secret) { console.error("AGENT_GAMES_HMAC_SECRET required"); process.exit(2); }
const BASE = process.argv[2];
const N = Number(process.argv[3] || 3);
const VKHASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xE8BF9bb3A4A63385B6c1e0e4F44AE23c883c16C3";

for (let i = 0; i < N; i++) {
  const t = {
    task_id: `latency-probe-${Date.now()}-${i}`,
    type: "agent-games.proof-gatekeeper.v1",
    mode: "competition",
    input: {
      registered_vk: VKHASH, proof_vk: VKHASH,
      minimum: "100", public_balance: "500",
      expiry_block: "20000000", current_block: "19999999",
      recipient: ADDR, condition_recipient: ADDR,
      amount: "10", max_transfer: "100",
      proof_tx: "0x" + crypto.randomBytes(32).toString("hex"),
    },
  };
  const body = JSON.stringify(t);
  const sig = crypto.createHmac("sha256", Buffer.from(secret, "utf8")).update(body).digest("hex");
  const t0 = Date.now();
  const res = await fetch(BASE + "/", { method: "POST", headers: { "Content-Type": "application/json", "x-agent-games-signature": sig }, body });
  const j = await res.json().catch(() => ({}));
  console.log(`probe ${i}: HTTP ${res.status} ${j.decision}/${j.reason_code} proof=${!!j.proof} client=${Date.now() - t0} ms server=${j.server_ms} ms proof=${j.proof_ms} ms`);
}
