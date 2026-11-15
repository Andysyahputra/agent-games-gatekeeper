// Encoding experiment for the gatekeeper circuit.
// Tries candidate field-element encodings, runs fullProve + verify.
// Usage: node test/exp1.mjs
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const WASM = "./circuits/gatekeeper.wasm";
const ZKEY = "./circuits/gatekeeper_final.zkey";
const VK = JSON.parse(fs.readFileSync("./circuits/vk.json", "utf8"));

const VKHASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xE8BF9bb3A4A63385B6c1e0e4F44AE23c883c16C3"; // user's Agentic EVM wallet

// Candidate A: hashes/addresses as BigInt(hex string); numbers as decimal strings;
// taskId as small integer; salt as small integer.
const inputA = {
  registeredVkHash: BigInt(VKHASH).toString(),
  proofVkHash: BigInt(VKHASH).toString(),
  minimum: "100",
  publicBalance: "500",
  expiryBlock: "20000000",
  currentBlock: "19999999",
  recipient: BigInt(ADDR).toString(),
  conditionRecipient: BigInt(ADDR).toString(),
  amount: "10",
  maxTransfer: "100",
  decision: "1",
  taskId: "42",
  salt: "12345",
};

async function attempt(name, input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ms = Date.now() - t0;
    const proofBytes = Buffer.byteLength(JSON.stringify(proof));
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    console.log(`[${name}] fullProve OK in ${ms} ms, proof JSON ${proofBytes} bytes, publicSignals=${publicSignals.length}, verify=${ok}`);
    console.log(`  publicSignals: ${JSON.stringify(publicSignals)}`);
    return { ok, proof, publicSignals, ms };
  } catch (e) {
    console.log(`[${name}] fullProve FAILED in ${Date.now() - t0} ms: ${String(e).slice(0, 300)}`);
    return { ok: false, error: String(e) };
  }
}

await attempt("A-valid-decision1", inputA);
// Wrong decision with all conditions passing must FAIL (decision = AND of checks).
await attempt("A-wrong-decision0", { ...inputA, decision: "0" });
// One failing condition + decision 1 must FAIL.
await attempt("A-balance-low-decision1", { ...inputA, publicBalance: "50" });
// One failing condition + decision 0 must SUCCEED (correct rejection is provable).
await attempt("A-balance-low-decision0", { ...inputA, publicBalance: "50", decision: "0" });
