# Proof Gatekeeper — zkVerify Agent Games (Track 1)

Agent endpoint that receives signed Proof Gatekeeper tasks, decides
APPROVE/REJECT with the 7 documented trap checks, proves the decision with
the official gatekeeper Groth16 circuit, and returns the proof in the
signed response. Built 2026-11-15 for boskuhh.

## Live endpoint

- **Stable URL (use this at registration):**
  `https://agent-games-gatekeeper-pearl.vercel.app`
- Also: `https://agent-games-gatekeeper-andy-syahputras-projects.vercel.app`
- Vercel project `agent-games-gatekeeper`, account **andysyahputra**
  (Hobby plan), SSO protection disabled, no framework, Node serverless
  function `api/index.js`.
- `GET /` → health check `{"status":"ok", ...}` (no auth needed).

## Current state (2026-11-15 ~08:10 WIB)

**Deployed and fully tested, but NOT yet usable for competition:**
no HMAC secret is configured (deliberately — the real secret is issued
once at registration). Until the user sets it, every POST returns
`503 {"error":"hmac_secret_not_configured"}` (fail closed). A TEST-ONLY
secret was set temporarily to verify the deployed endpoint end-to-end,
then **removed**; the final deployment was verified clean (GET 200,
POST 503).

## What the user must do (registration)

1. Register at https://agentgames.zkverify.io — sign in with **X
   @Andysyahputra__** (NOT wallet SIWE).
2. Attach the prize wallet: Binance Agentic EVM
   `0xE8BF9bb3A4A63385B6c1e0e4F44AE23c883c16C3`.
3. At registration the platform shows, exactly once:
   - the **32-byte HMAC secret** → save it, then set it as Vercel env var
     **`AGENT_GAMES_HMAC_SECRET`** (production) on the
     `agent-games-gatekeeper` project and redeploy;
   - the **Kurier mainnet API key** → set as **`KURIER_API_KEY`**
     (production) the same way.
4. Register the endpoint URL above, run the platform's signed preflight
   + ≥1 practice task. If preflight rejects the HMAC, the only code to
   touch is `lib/hmac.js` (secret-encoding / header-format assumptions
   are isolated there).
5. Optional env vars: `KURIER_CHAIN_ID` (aggregation destination chain;
   unset = none), `KURIER_POLL_MS` (default 5000), `SEEN_SET_PATH`.

No account, wallet, or key was created by this build. No money spent.

## How it works

`POST /` with the task envelope
(`agent-games.proof-gatekeeper.v1`, `task_id`, `input{...}`), in order:

1. **HMAC first:** `x-agent-games-signature` is verified against the RAW
   body before any parsing. Bad/missing → 401. No secret → 503.
   Convention: lowercase hex HMAC-SHA256(secret, rawBody); an optional
   `sha256=` prefix and base64 digests are tolerated. Secret encoding:
   the platform shows the secret once as a 64-char hex string and signs
   with the **UTF-8 bytes of that string** — proven by preflight 401s on
   2026-11-15 with two rotated secrets when the endpoint hex-decoded it.
   `lib/hmac.js` now tries every plausible reading (UTF-8 string, then
   hex-decoded, then base64-decoded 32 bytes) and signs each response
   with the SAME reading that verified the request, so the platform can
   verify our signature with its own convention. See `lib/hmac.js` and
   `test/hmac-conventions.mjs` (4/4: UTF-8 reading → 200, hex reading →
   200, bad sig → 401, health → 200).
2. **Idempotency:** `task_id` is the idempotency key. A redelivery
   returns the byte-identical cached response (same body + signature).
3. **Trap checks** (first failing trap wins as `reason_code`):
   `VK_SUBSTITUTION` (proof_vk ≠ registered_vk) →
   `THRESHOLD_MISMATCH` (public_balance < minimum) →
   `PROOF_REUSED` (proof_tx already in seen-set) →
   `EXPIRED_CONDITION` (current_block > expiry_block) →
   `RECIPIENT_MISMATCH` (recipient ≠ condition_recipient) →
   `AMOUNT_OVERFLOW` (amount > max_transfer) →
   `VALID_CONDITION` → APPROVE.
4. **Groth16 proof** (`snarkjs` 0.7.6, official `gatekeeper.wasm` /
   `gatekeeper_final.zkey`, vkHash
   `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`).
   decision = AND of the five circuit checks. A wrong decision cannot
   produce a witness (fullProve throws `Assert Failed ... line: 102`) —
   that is correct: the decision is returned WITHOUT a proof, fail
   closed, never approve on error. `PROOF_REUSED` with all five checks
   passing is the normal no-proof case (platform excludes these from
   the proof bonus).
5. **Kurier** (`lib/kurier.js`, docs: docs.zkverify.io): only when
   `KURIER_API_KEY` is set. `POST {API_URL}/submit-proof/{key}` with
   `{proofType:"groth16", vkRegistered:true,
   proofOptions:{library:"snarkjs", curve:"bn254"},
   proofData:{proof, publicSignals, vk: vkHash}}` (the gatekeeper vk is
   already registered on zkVerify mainnet by the platform, so no
   `register-vk` call). Polls `job-status` at 1 s intervals up to
   `KURIER_POLL_MS` (5 s) and returns the tx hash as soon as the job
   reaches **Submitted** — never waits for finalization (~27 s). Without
   a key, `proof_tx` echoes the task's `proof_tx` and the proof is
   returned in the response. **Kurier submission is implemented but
   UNTESTED live** (no key exists yet); the tx-hash field name in
   job-status responses is assumed (`txHash`/`transactionHash`/
   `extrinsicHash`/`hash`) — verify at preflight.
6. **Signed response:** `{decision, reason_code, proof_tx, proof,
   publicSignals, server_ms, proof_ms}` (+ `kurier_job_id` /
   `kurier_status` when a submission was attempted), signed with
   `x-agent-games-signature` over the raw response body.

## Confirmed circuit input encodings (by local experiment)

13 input signals, in order: `registeredVkHash, proofVkHash, minimum,
publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
amount, maxTransfer, decision, taskId, salt`.

- **vkHash / address:** raw `BigInt("0x...")`, as a decimal string.
- **minimum, publicBalance, expiryBlock, currentBlock, amount,
  maxTransfer:** plain decimal strings.
- **decision:** `"1"` approve / `"0"` reject.
- **taskId:** any field element. Numeric ids pass through directly;
  non-numeric ids (UUID / `"task-..."` strings) are `sha256(utf8) mod p`.
- **salt:** PRIVATE, fresh random 128-bit value per proof.
- **publicSignals (13, all verify OK):** `[0] = Poseidon([salt, taskId])`
  (salt first — confirmed exactly); `[1] = hash(registeredVkHash)`,
  `[2] = hash(proofVkHash)` — circuit-internal hash, NOT plain
  `Poseidon([x])`, NOT sha256 mod p, NOT `Poseidon([x,0])`/`[0,x]`;
  exact function unidentified, but the endpoint never needs it
  (fullProve returns publicSignals). `[3..12]` echo minimum,
  publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId.
- Proof JSON ~720 bytes (718–726 observed). Verified with
  `snarkjs groth16 verify` against `circuits/vk.json` (nPublic 13).

## Latency (measured 2026-11-15)

| measurement | value |
|---|---|
| Proof generation, local (this VM, warm) | 216–380 ms (first 0.9–1.2 s) |
| Proof generation, Vercel server-side (`proof_ms`) | **380 ms warm / 888 ms cold** |
| Full POST end-to-end, Vercel warm (client-observed) | 500–700 ms |
| Full POST end-to-end, Vercel cold (client-observed) | ~1.6 s |
| Cold GET health | 0.7–1.35 s |
| 60 s task window | headroom ~58 s warm, ~58 s cold |

Caveats: client-observed first-request latencies from this VM were
erratic twice (29.8 s once, 282 s once) while server-side timing in the
same conditions stayed ~0.9 s — those stalls are in this VM's egress
proxy path (plain curl POSTs also hung there), not in the function.
The platform's own calls will not go through this VM; confirm with the
platform preflight. The deployment reports `functionTimeout: 300` and
Fluid compute, so the 10 s Hobby cap in `vercel.json` (`maxDuration:
10`) did not cut off the slow observed requests — but a cold proof
still completes server-side in <1 s, so the cap is not a practical
risk; if a future cold start ever approaches it, the fix is Vercel Pro
(60 s+) or a warmer.

## Test results

`node test/run-tests.mjs` (local) and against the deployed URL with the
temporary test secret — **12/12 PASS both times**:

- valid APPROVE (proof verifies OK), replay of same `task_id` →
  byte-identical cached response, bad HMAC → 401, missing HMAC → 401,
  all six traps → correct REJECT + `reason_code`, proofs verify OK
  for the five provable rejects, `proof: null` for PROOF_REUSED,
  string `task_id` APPROVE (proof verifies), GET health 200.
- Wrong-decision cases confirmed at circuit level: decision 0 with all
  checks passing, and decision 1 with any check failing, both fail
  witness generation (fail closed).

## Seen-set / idempotency persistence — honest limitation

In-memory + file-backed JSON (`data/seen.json` locally,
`/tmp/gatekeeper-seen.json` on Vercel). On Vercel, instances do NOT
share state and `/tmp` is discarded on recycle, so cross-instance
`PROOF_REUSED` detection is best-effort only. A durable cross-instance
store (Vercel KV / Upstash Redis / Postgres) is the fix if the platform
replays across instances; it is NOT set up here. The deployed instance
correctly showed `seenProofTx: 7, cachedResponses: 8` after the remote
test run.

## Files

- `api/index.js` — Vercel entrypoint; `server.js` — local server
  (`AGENT_GAMES_HMAC_SECRET=<test-only> node server.js`).
- `lib/handler.js` — request flow; `lib/hmac.js` — HMAC (swappable);
  `lib/circuit.js` — encodings + proving; `lib/kurier.js` — Kurier;
  `lib/store.js` — seen-set + response cache.
- `circuits/` — official wasm/zkey/vk (sha256 in deploy log:
  wasm `be00aefe…`, zkey `adfe95a4…`).
- `test/run-tests.mjs` — full suite; `test/latency-probe.mjs` —
  latency probe; `test/exp2.mjs`, `test/exp3.mjs` — encoding
  experiments; `scripts/deploy.py` — Vercel REST deploy (reuses the
  registered Vercel credential; `/opt/hatch/bin/vercel` is only an MCP
  wrapper and is not connected, `vercel whoami` is not a real subcommand).

## Redeploy

```bash
cd ~/workspace/agent-games/gatekeeper
python3 scripts/deploy.py   # creates a new production deployment
```

Set env vars in the Vercel dashboard (project
`agent-games-gatekeeper` → Settings → Environment Variables,
Production) or via the API, then redeploy — env changes need a new
deployment to take effect. Never commit a real secret anywhere in this
repo.
