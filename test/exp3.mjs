// Differential experiment: which public signal moves when one input changes?
// Also: wrong-decision must fail; correct-reject (decision 0 + failing check) must prove.
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const VKHASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xE8BF9bb3A4A63385B6c1e0e4F44AE23c883c16C3";
const VK = JSON.parse(fs.readFileSync("./circuits/vk.json", "utf8"));

console.log("vkHash as decimal:", BigInt(VKHASH).toString());
console.log("addr as decimal:  ", BigInt(ADDR).toString());
console.log("bn128 p:          21888242871839275222246405773286655761059516991489954752536083426433803193732281");

const base = {
  registeredVkHash: BigInt(VKHASH).toString(),
  proofVkHash: BigInt(VKHASH).toString(),
  minimum: "100", publicBalance: "500",
  expiryBlock: "20000000", currentBlock: "19999999",
  recipient: BigInt(ADDR).toString(), conditionRecipient: BigInt(ADDR).toString(),
  amount: "10", maxTransfer: "100", decision: "1", taskId: "42", salt: "12345",
};

async function attempt(name, input) {
  const t0 = Date.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, "./circuits/gatekeeper.wasm", "./circuits/gatekeeper_final.zkey");
    const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
    console.log(`[${name}] OK ${Date.now() - t0}ms verify=${ok} pub=${JSON.stringify(publicSignals)}`);
  } catch (e) {
    console.log(`[${name}] FAIL ${Date.now() - t0}ms: ${String(e).slice(0, 200)}`);
  }
}

await attempt("base", base);
await attempt("salt-only-change", { ...base, salt: "99999" });
await attempt("taskId-only-change", { ...base, taskId: "43" });
await attempt("wrong-decision0-all-pass", { ...base, decision: "0" });
await attempt("balance-low-decision1", { ...base, publicBalance: "50" });
await attempt("balance-low-decision0", { ...base, publicBalance: "50", decision: "0" });
await attempt("vk-mismatch-decision0", { ...base, proofVkHash: BigInt("0x1111111111111111111111111111111111111111111111111111111111111111").toString(), decision: "0" });
await attempt("vk-mismatch-decision1", { ...base, proofVkHash: BigInt("0x1111111111111111111111111111111111111111111111111111111111111111").toString(), decision: "1" });
