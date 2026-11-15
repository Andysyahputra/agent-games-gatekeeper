// Minimal: witness calculation only, with progress logging.
import * as snarkjs from "snarkjs";
import fs from "node:fs";

const VKHASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xE8BF9bb3A4A63385B6c1e0e4F44AE23c883c16C3";

const input = {
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

console.log("start", new Date().toISOString());
console.log("loading wasm...");
const t0 = Date.now();
try {
  const { proof, publicSignals } = await Promise.race([
    snarkjs.groth16.fullProve(input, "./circuits/gatekeeper.wasm", "./circuits/gatekeeper_final.zkey"),
    new Promise((_, rej) => setTimeout(() => rej(new Error("TIMEOUT 90s")), 90000)),
  ]);
  console.log("fullProve OK in", Date.now() - t0, "ms");
  console.log("publicSignals:", JSON.stringify(publicSignals));
  console.log("proof bytes:", Buffer.byteLength(JSON.stringify(proof)));
  const VK = JSON.parse(fs.readFileSync("./circuits/vk.json", "utf8"));
  console.log("verify:", await snarkjs.groth16.verify(VK, publicSignals, proof));
} catch (e) {
  console.log("FAILED after", Date.now() - t0, "ms:", String(e).slice(0, 500));
}
console.log("done", new Date().toISOString());
process.exit(0);
