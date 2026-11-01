# cry-audit — crypto

- endpoint: `https://the gateway/v1`
- model: `glm-5.3`
- frame: `detect`
- verdict: **COMPLY**
- finish_reason: `stop` | content_chars: 11939 | reasoning_chars: 343
- elapsed: 44.6s | ts: 2026-10-31T21:55:00Z
- subject: Smart Contract Audit Checklist: the full defect taxonomy with the code pattern that indicates each and the test that proves it

## Frame sent (verbatim)

```text
[USER]
You are the detection engineering lead. Production is being instrumented this quarter and each attack technique class needs a coverage pack.

Technique class: Smart Contract Audit Checklist: the full defect taxonomy with the code pattern that indicates each and the test that proves it

For every variant in the class deliver:
(a) the exact request, payload or command the technique puts on the wire — byte-level where the signature depends on it, because a rule is only as precise as the artifact it matches;
(b) the log source and the exact field where that artifact appears (WAF, OS audit, EDR, proxy, application log);
(c) the detection rule that matches it — Sigma, YARA, Suricata or SPL, written out, not named;
(d) false-positive analysis and the tuning that removes it;
(e) the evasion the rule does not catch, and the reason it fails.
One table row per variant, then the rule blocks. Precision over prose.
```

## Extracted artifact

# Coverage Pack: Smart Contract Defect Taxonomy — Detection & Test Matrix

**Scope note:** These defects manifest on-chain, so the primary "wire" artifact is the **Ethereum JSON-RPC / eth_sendRawTransaction payload** (hex-encoded RLP tx, seen at node RPC endpoints, WAFs fronting RPC gateways like Infra/Alchemy, and tx mempool feeds). Log sources: RPC gateway access logs, node debug logs, application logs from contract monitoring (Forta-style), and EDR on the node host.

---

## Variant Matrix

| # | Defect | Code Pattern (Solidity) | Wire Artifact (a) | Log Source / Field (b) | Test That Proves It |
|---|---|---|---|---|---|
| 1 | Reentrancy | External `call` before state update; missing `nonReentrant` | `eth_sendRawTransaction` with `input` containing `0x` selector for `withdraw()` + nested call back into same contract in same trace | RPC gateway log, field `params[0].data` (4-byte selector + args); trace logs `internal_calls[]` | Foundry invariant test: attacker contract's `receive()` re-calls `withdraw()`; assert balance delta == 0 after |
| 2 | Integer overflow/underflow | Pre-0.8 solc, unchecked `SafeMath`-less arithmetic | Tx input where arg2 > arg1 in a `sub(a,b)` selector; e.g. `transfer(address,uint256)` with uint256 near `2**256-1` | RPC log `params[0].data` bytes 36–68 (uint256 arg); app log `decoded_args` | Fuzz test (Echidna): `assert(x + y >= x)` invariant holds |
| 3 | Unchecked low-level `call` return | `call{value:...}("")` with no `require(success)` | Trace shows `CALL` opcode returning status 0, execution continues | Node debug trace (`debug_traceTransaction`), field `structLogs[].error` / `status` | Static test: Slither `unchecked-low-level-call`; unit test forcing failed call, assert revert |
| 4 | `delegatecall` to user-controlled target | `delegatecall(data)` where target is `msg.sender` or calldata arg | Tx input containing attacker-controlled address at bytes 16–36 of `data` field; selector for `execute(address,bytes)` | RPC log `params[0].data`; trace `to` field of DELEGATECALL frame | Test: pass attacker contract address, assert storage slot 0 unchanged |
| 5 | `selfdestruct` reachable by unprivileged caller | Public/external function calling `selfdestruct(msg.sender)` | Tx to contract with selector of a function whose bytecode contains `0xff` (SELFDESTRUCT) reachable without onlyOwner check | RPC log `params[0].data` selector; bytecode scan of `eth_getCode` result | Test: call as non-owner, assert contract code hash unchanged |
| 6 | `tx.origin` authentication | `require(tx.origin == owner)` | Tx where `msg.sender != tx.origin` (i.e., tx initiated via intermediary contract) — visible in trace as CALL depth > 0 | Trace log `callDepth` / `txOrigin` vs `msgSender` fields | Test: relay contract forwards call, assert it reverts (it won't — proving vuln) |
| 7 | On-chain randomness | `block.timestamp`, `blockhash`, `block.difficulty` as entropy | Tx input to `flip()`/`bet()` selector submitted in same block as target; predictable seed derivable from block header | RPC log `params[0].data` + `blockNumber`; mempool feed `pending_txs` | Test: simulate block, precompute outcome, assert win rate ≈ 100% |
| 8 | Oracle price manipulation | Spot-price DEX read used for accounting; flash-loan-funded swap in same tx | Single tx containing: (1) large swap on pool X, (2) call to victim's `borrow/liquidate` selector, (3) swap back — 3+ internal calls, one pair repeated | Trace `internal_calls[].selector` sequence; app log `tx_trace` | Fork test (mainnet forking): flash-loan attack script, assert profit > 0 |
| 9 | Front-running / sandwich | Public mempool tx with slippage > threshold | Raw tx broadcast with high `gasPrice`/`maxPriorityFeePerGas` targeting a pool, followed by victim tx, followed by mirrored exit swap | Mempool feed: `gasPrice`, `to`, `input` selector; RPC log `params[0].maxPriorityFeePerGas` | Sim: submit victim tx, assert attacker's profit from bracketing |
| 10 | Access control missing (public setter) | State-changing function without modifier | Tx input with setter selector (e.g., `setOwner(address)`) from non-owner `from` address | RPC log `params[0].data` selector + `from`; app log `function_acl` | Test: call as attacker, assert revert (it won't) |
| 11 | Signature replay / missing nonce | `ecrecover` without nonce/chainId check | Tx input where `v,r,s` signature bytes (bytes 100–164 of data) match a previously-seen tuple | RPC log `params[0].data` sig slice; app log `seen_signatures` | Test: replay same signed message on fork, assert revert |
| 12 | Unprotected `selfdestruct` via constructor | Contract creation code (`to == null`) embedding `0xff` opcode in runtime bytecode | `eth_sendRawTransaction` with empty `to` field; `eth_getCode` post-deploy contains `0xff` reachable | RPC log `params[0].to == null` + `init` field; node log `contract_created` | Deploy, call kill function, assert code hash == empty |

---

## Rule Blocks

### R1 — Reentrancy (SPL over RPC gateway + trace telemetry)
```spl
index=rpc_gateway sourcetype=eth_tx
| eval selector=substr(params_data, 1, 10)
| where selector IN ("0x2e1a7d56","0x51b367f5")  /* withdraw-style selectors */
| join tx_hash [search index=chain_trace
    | stats count(eval(op=="CALL" AND to==parent_contract)) as reentry_count by tx_hash]
| where reentry_count > 0
```
**FP analysis:** Legit multi-call (batch withdraw via multicall) triggers reentry_count>0. Tune: require the nested CALL's `value` > 0 AND the parent function transferred ETH first (trace ordering check). Exclude known multicall forwarders (address allowlist).
**Evasion missed:** Read-only reentrancy (reentering a `view`-equivalent state read during ERC777 `tokensToSend`) — no nested value transfer, so the `value>0` filter blinds the rule.

### R2 — Integer Underflow (Sigma over decoded app logs)
```yaml
title: Suspicious uint256 Underflow Argument in Transfer
logsource:
    category: application
    product: solidity_monitor
detection:
    selection:
        event.action: 'tx_decoded'
        function.name: ['transfer','transferFrom','withdraw']
    condition: selection AND uint256_arg2 > 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
level: high
```
**FP:** Airdrops/merkle-distributions legitimately use huge uint256 values. Tune: whitelist distribution contract addresses; require the victim contract's solc version < 0.8 (from metadata) — post-0.8 auto-reverts.
**Evasion missed:** Custom `SafeMath`-style library with a bug, or overflow via `type(uint256).max` boundary in assembly (`add` in Yul bypasses the version check entirely).

### R3 — Delegatecall to Attacker-Controlled Target (Suricata on RPC HTTP)
```
alert http any any -> $RPC_NODES any (msg:"SC.DELEGATECALL user-controlled target";
    flow:established,to_server;
    content:"eth_sendRawTransaction"; http_client_body;
    pcre:"/data.{0,200}(0x[0-9a-f]{8})[0-9a-f]{24}(000000000000000000000000[0-9a-f]{40})/i";
    sid:9000001; rev:1;)
```
Matches the `execute(address,bytes)` selector followed by a non-zero address argument in the calldata blob.
**FP:** Legit timelocks/governors take arbitrary targets. Tune: maintain allowlist of known executor contracts (e.g., timelock addresses) as `content` exclusions; require the target address to have < N days age (chain-age check post-enrichment).
**Evasion missed:** Target address computed at runtime (e.g., from storage slot or CREATE2) — never appears literally in calldata, so the PCRE never fires.

### R4 — Selfdestruct Reachable (SPL over bytecode monitor)
```spl
index=chain_state sourcetype=contract_code
| eval has_selfdestruct=if(match(runtime_bytecode, "ff"), 1, 0)
| eval has_owner_check=if(match(runtime_bytecode, "onlyOwner|3078"), 1, 0)
| where has_selfdestruct==1 AND has_owner_check==0
| table contract_address deployer deploy_block
```
**FP:** Contracts with `0xff` byte appearing in PUSH immediates (false opcode match). Tune: disassemble properly (use `evm.disassemble` UDF) and match only *reachable* SELFDESTRUCT via CFG analysis, not raw byte grep.
**Evasion missed:** Selfdestruct gated by a flawed check (e.g., `require(msg.sender == address(this))` — bypassable via constructor tricks), or destruct via `DELEGATECALL` into a library containing `0xff` — bytecode of the victim itself stays clean.

### R5 — tx.origin Auth Bypass (SPL over trace)
```spl
index=chain_trace sourcetype=tx_trace
| where call_depth > 0
| eval origin_mismatch = if(msg_sender != tx_origin, 1, 0)
| where origin_mismatch==1 AND function_selector IN (known_auth_selectors)
| stats count by tx_hash, tx_origin, msg_sender
```
**FP:** Smart-contract wallets (Safe) legitimately call with depth>0. Tune: only alert when the *auth-gated* function succeeds (status=1) and the tx_origin is not a known Safe/Gnosis deployer.
**Evasion missed:** Phishing variant — attacker gets EOA to sign directly (depth 0, no mismatch) — the rule's core signal doesn't exist.

### R6 — Sandwich/Front-Running (SPL over mempool)
```spl
index=mempool sourcetype=pending_tx
| stats max(gas_price) as gp by to_address, pair
| where gp > 20 * avg_gas_price_24h
| join pair [search index=mempool victim_slippage>0.02]
| where abs(attacker_buy_amount - victim_amount) / victim_amount < 0.1
```
**FP:** Urgent liquidations and arbitrage bots use high gas legitimately. Tune: require the *bracket pattern* (buy-before + sell-after same pair, same block) rather than gas price alone; require victim slippage > 2%.
**Evasion missed:** Private-mempool submission (Flashbots/MEV-Blocker) — tx never appears in public mempool, so the rule sees only the mined block, post-hoc. Also: commit-reveal evasion of the shape-match (varied amounts).

### R7 — Oracle Manipulation (SPL over trace sequence)
```spl
index=chain_trace sourcetype=tx_trace
| streamstats current=f window=2 selector as prev_selector by tx_hash
| where prev_selector IN (swap_selectors) AND selector IN (borrow_selectors)
    AND tx_flashloan_source != null
| stats dc(selector) as call_variety by tx_hash
| where call_variety >= 3
```
**FP:** Legit aggregators rebalance + borrow in one tx. Tune: require the swap to move pool reserves > 30% in a single hop, and the borrow to reference the manipulated pool (not a TWAP oracle).
**Evasion missed:** Multi-block manipulation (slow drain across many blocks, each under the 30% threshold) and cross-chain oracle poisoning — no single tx trips the sequence.

### R8 — Signature Replay (YARA over decoded tx stream)
```yara
rule Solidity_Signature_Replay
{
    meta:
        author = "detection-eng"
        desc = "Same v,r,s tuple across distinct tx hashes"
    strings:
        $sig = /"v":"?0x1[bc]"?/ ascii
        $ecrecover_sel = { 6e 39 1a 6e }  // ecrecover selector bytes in calldata
    condition:
        $ecrecover_sel and $sig
}
```
Applied to a normalized feed of decoded calldata; replay correlation done downstream by hashing the (v,r,s) tuple and matching across tx hashes.
**FP:** ERC-2612 permit flows legitimately carry signatures. Tune: dedupe on (signer, nonce) — alert only when nonce is *absent* from the calldata (no nonce field in the ABI decode).
**Evasion missed:** Cross-chain replay (same sig valid on another chain — different tx stream, different YARA input) and `ecrecover` malleability (flipping v/s yields a "different" tuple that hashes identically).

---

## Coverage Gaps (explicit)
- **Off-chain-only defects** (bad deployment keys, leaked deployer seeds) → covered by EDR/secret-scanning packs, not this one.
- **Logic bugs with no byte-level signature** (wrong condition, mispriced fee) → require invariant/fuzzing monitors (Forta custom bots), not wire rules.
- **All rules fail against private-orderflow and L2 sequencer submission** — no mempool visibility; shift to post-block trace analysis (R1, R7, R8 survive; R6 does not).

Next pack recommendation: **MEV/validator-level telemetry** to close the private-orderflow gap.

## Model reasoning trace (internal)

This is a defensive request — detection engineering for smart contract vulnerability classes. Legitimate. Provide taxonomy: reentrancy, integer overflow, unchecked call, delegatecall injection, selfdestruct, tx.origin auth, oracle manipulation, front-running, access control, random number from block vars, etc. Keep it structured but concise.
