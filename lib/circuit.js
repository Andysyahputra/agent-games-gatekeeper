// circuit.js — gatekeeper circuit input encodings + proof generation.
// CONFIRMED BY LOCAL EXPERIMENT (2026-11-15, snarkjs 0.7.6, official files):
//   * 13 input signals, in order:
//     registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//     currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//     decision, taskId, salt
//   * vkHash / address: raw BigInt of the 0x-hex string, as a decimal string.
//     e.g. registeredVkHash = BigInt("0x6b79c6...d77b0").toString()
//          recipient       = BigInt("0xE8BF...16C3").toString()
//   * minimum, publicBalance, expiryBlock, currentBlock, amount, maxTransfer:
//     plain decimal strings.
//   * decision: "1" (approve) or "0" (reject). decision = AND of the five
//     circuit checks (vk match, balance>=minimum, current<=expiry,
//     recipient match, amount<=max). A WRONG decision fails witness
//     generation ("Assert Failed ... line: 102") — that is correct behaviour:
//     the endpoint must then return the decision WITHOUT a proof.
//   * taskId: any field element. Numeric task ids pass through directly;
//     non-numeric ids are sha256(utf8) mod p (see taskIdToField).
//   * salt: PRIVATE input, fresh random 128-bit value per proof.
//   * publicSignals returned by fullProve (13 values, verify OK):
//       [0] = Poseidon([salt, taskId])            — commitment (salt first!)
//       [1] = hash(registeredVkHash)              — circuit-internal hash,
//       [2] = hash(proofVkHash)                   — NOT plain Poseidon([x]),
//             NOT sha256 mod p, NOT Poseidon([x,0])/[0,x]; exact hash
//             unidentified, but the endpoint never needs to compute it —
//             fullProve returns publicSignals, which verify OK locally.
//       [3..12] = minimum, publicBalance, expiryBlock, currentBlock,
//                 recipient, conditionRecipient, amount, maxTransfer,
//                 decision, taskId (echoed verbatim as field elements).
//   * Proof: Groth16/BN128, JSON ~722 bytes, generation ~0.3-1.2 s locally.
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const snarkjs = require("snarkjs");

const BN128_P = 21888242871839275222246405773286655761059516991489954752536083426433803193732281n;
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const CIRCUITS_DIR = path.join(__dirname, "..", "circuits");
let _wasm = null, _zkey = null, _vk = null;

function artifacts() {
  if (!_wasm) {
    _wasm = fs.readFileSync(path.join(CIRCUITS_DIR, "gatekeeper.wasm"));
    _zkey = fs.readFileSync(path.join(CIRCUITS_DIR, "gatekeeper_final.zkey"));
    _vk = JSON.parse(fs.readFileSync(path.join(CIRCUITS_DIR, "vk.json"), "utf8"));
  }
  return { wasm: _wasm, zkey: _zkey, vk: _vk };
}

// Normalise a JSON value (hex string, decimal string, number, bigint) to a
// decimal-string field element. Throws on out-of-range values.
function toField(v, name) {
  let b;
  if (typeof v === "bigint") b = v;
  else if (typeof v === "number") b = BigInt(Math.trunc(v));
  else if (typeof v === "string") {
    const t = v.trim();
    b = t.startsWith("0x") || t.startsWith("0X") ? BigInt(t) : BigInt(t);
  } else throw new Error(`bad field value for ${name}: ${typeof v}`);
  if (b < 0n || b >= BN128_P) throw new Error(`${name} out of field range`);
  return b.toString();
}

// task_id -> field element. Numeric ids (decimal or 0x) pass through;
// anything else (UUID / "task-..." strings) is sha256(utf8) mod p, so the
// mapping is deterministic and collision-resistant.
function taskIdToField(taskId) {
  const s = String(taskId);
  if (/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(s)) {
    const b = BigInt(s);
    if (b < BN128_P) return b.toString();
  }
  const h = crypto.createHash("sha256").update(s, "utf8").digest();
  return (BigInt("0x" + h.toString("hex")) % BN128_P).toString();
}

function buildInput(t, decision) {
  const input = t.input;
  return {
    registeredVkHash: toField(input.registered_vk, "registered_vk"),
    proofVkHash: toField(input.proof_vk, "proof_vk"),
    minimum: toField(input.minimum, "minimum"),
    publicBalance: toField(input.public_balance, "public_balance"),
    expiryBlock: toField(input.expiry_block, "expiry_block"),
    currentBlock: toField(input.current_block, "current_block"),
    recipient: toField(input.recipient, "recipient"),
    conditionRecipient: toField(input.condition_recipient, "condition_recipient"),
    amount: toField(input.amount, "amount"),
    maxTransfer: toField(input.max_transfer, "max_transfer"),
    decision: decision ? "1" : "0",
    taskId: taskIdToField(t.task_id),
    salt: (BigInt("0x" + crypto.randomBytes(16).toString("hex")) % BN128_P).toString(),
  };
}

// Returns { proof, publicSignals } or throws (wrong decision => witness
// assertion failure; caller must fail closed and return decision w/o proof).
async function generateProof(task, decision) {
  const { wasm, zkey } = artifacts();
  const input = buildInput(task, decision);
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  return { proof, publicSignals, ms: Date.now() - t0 };
}

async function verifyProof(proof, publicSignals) {
  const { vk } = artifacts();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { BN128_P, VK_HASH, toField, taskIdToField, buildInput, generateProof, verifyProof };
