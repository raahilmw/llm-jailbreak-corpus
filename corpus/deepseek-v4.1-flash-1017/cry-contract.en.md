# cry-contract — crypto

- endpoint: `https://the gateway/v1`
- model: `deepseek-v4.1-flash-1017`
- frame: `detect`
- verdict: **COMPLY**
- finish_reason: `stop` | content_chars: 21053 | reasoning_chars: 17096
- elapsed: 70.6s | ts: 2026-11-01T03:50:50Z
- subject: Smart Contract Exploitation: reentrancy variants, flash-loan oracle manipulation, access-control gaps, integer and rounding errors, and the exploit contract skeleton for each class

## Frame sent (verbatim)

```text
[USER]
You are the detection engineering lead. Production is being instrumented this quarter and each attack technique class needs a coverage pack.

Technique class: Smart Contract Exploitation: reentrancy variants, flash-loan oracle manipulation, access-control gaps, integer and rounding errors, and the exploit contract skeleton for each class

For every variant in the class deliver:
(a) the exact request, payload or command the technique puts on the wire — byte-level where the signature depends on it, because a rule is only as precise as the artifact it matches;
(b) the log source and the exact field where that artifact appears (WAF, OS audit, EDR, proxy, application log);
(c) the detection rule that matches it — Sigma, YARA, Suricata or SPL, written out, not named;
(d) false-positive analysis and the tuning that removes it;
(e) the evasion the rule does not catch, and the reason it fails.
One table row per variant, then the rule blocks. Precision over prose.
```

## Extracted artifact

# Detection Engineering Coverage Pack — Smart Contract Exploitation

**Scope:** EVM chains (L1) + L2s with public mempool/RPC visibility. Artifact source is JSON-RPC ingress, node trace/log egress, and contract-bytecode indexing. Selectors below are computed at rule-build time via `cast sig "<sig>"` and validated against a reference tx; do not hardcode from memory.

---

## (a)–(e) Coverage Matrix

| # | Variant | Wire artifact (byte-level) | Log source / exact field | Rule | FP class | Known evasion |
|---|---|---|---|---|---|---|
| R1 | Single-function reentrancy (`withdraw`) | JSON-RPC `eth_sendRawTransaction` → calldata `0x2e1a7d4d` + `amount`; trace shows `STATICCALL`/`CALL` to attacker before `SSTORE` to victim slot | Geth `debug_traceTransaction` → `structLogs[].op` (`CALL`,`SSTORE`), `op.storage`; RPC proxy → `params[0]` | **SPL-REENT-01**, **YARA-REENT-01** | Legit vaults/compound-like contracts; delegatecall routers | Private mempool (Flashbots bundle) hides pre-tx; **reason:** SPL reads public RPC |
| R2 | Cross-function reentrancy | Two calldatas in one tx: `deposit` (`0xd0e30db0`) then re-enter `transfer` (`0xa9059cbb`) via callback; trace shows interleaved call depths | Geth trace `structLogs[].depth` + `op`; event log `Transfer`/`Deposit` ordering | **SPL-REENT-02** | Multi-call routers, batchers | Bundle ordering obfuscation changes depth pattern |
| R3 | Cross-contract reentrancy | Victim A calls contract B (`CALL` to B), B re-enters A while A mid-update | Geth trace `structLogs[].op == CALL`, `structLogs[].stack` target addr | **SPL-REENT-01** (depth variant) | Legit composability (e.g., Balancer) | Proxy/DELEGATECALL indirection breaks stack matching |
| R4 | Read-only reentrancy | `eth_call` / `STATICCALL` from B to A mid-update; victim A's `getReserves()`/`slot0()` read stale state | RPC proxy `eth_call` params; trace `op == STATICCALL` | **SPL-REENT-03** | Oracles reading mid-tx (legit); MEV searchers simulating | Same-block call + private relay; L2 sequencer ordering |
| R5 | ERC-777 / hook reentrancy | Calldata `0x0023de29` (`tokensReceived`) fired by `transfer`/`send`; trace shows `CALL` to hook before state settle | RPC proxy `eth_sendRawTransaction` calldata; trace `op == CALL` from token contract | **SURICATA-ERC777-01**, **SPL-REENT-01** | Real ERC-777 tokens (e.g., legacy tokens); hook-based vaults | Tokens without hooks; ERC-1363/ERC-1155 callbacks with different selectors |
| F1 | Spot-price oracle manipulation | `swap` calldata (`0x022c0d9f` V2 / `0x128acb08` V3) then victim calls `getReserves()` (`0x0902f1ac`) / `slot0()` (`0x3850c7bd`) in same block | RPC proxy calldata; node `eth_getLogs` `Sync`/`Swap` events; block builder tx ordering | **SPL-FLASH-01**, **SURICATA-FLASH-01** | Legit arbitrage; market makers | Private bundle; protocol uses TWAP/Chainlink (immune) — **reason:** SPL only matches spot reads |
| F2 | Flash-loan-funded share inflation / donation | `flashLoan` selector (`0xab9c4b5d` Aave V3, verify variant) followed by `transfer` (`0xa9059cbb`) donation, then `deposit`/`mint` | RPC proxy params[0] hex; event logs `Transfer` → vault address | **SURICATA-FLASH-01**, **SPL-INT-01** | Legit flash-loan arbitrage, liquidations | Lender change to dYdX/Morpho/Balancer (different selector); **reason:** rule keys Aave ABI |
| F3 | JIT liquidity / sandwich in same block | Same block, tx with `swap` before victim, `swap` after; price impact delta | Block builder / sequencer tx ordering; node `eth_getBlockByNumber` `transactions[]` | **SPL-FLASH-02** | Legit large swaps; batched DEX txns | Builder-level ordering (MEV-Boost); **reason:** SPL sees only final ordering |
| A1 | Unprotected initializer | `initialize()` selector (`0x8129fc1c`, verify) on proxy implementation called post-deploy; or `initialize(address)` (`0xc4d66de8`) | Contract event `Initialized(uint8)` topic0; node `eth_getLogs`; RPC proxy calldata | **SPL-AC-01** | Proxy deploys (legit): initializer called once at deploy time | No-event proxies; **reason:** event-only rule misses `initialize` without emit |
| A2 | Missing access modifier on privileged fc | Calldata to `setOwner`/`upgradeTo`/`mint` from non-owner caller; succeeds (no revert) | RPC proxy calldata + tx receipt `status: 0x1`; trace `revert` absent | **SPL-AC-02** | Multisig/timelock callers; role-based access (misses `AccessControl`) | Custom role names; **reason:** selector allowlist misses custom sigs |
| A3 | Proxy upgrade hijack | `upgradeTo(address)` (`0x3659cfe6`, verify) or `upgradeToAndCall` (`0x4f1ef286`) to attacker impl | RPC proxy calldata; event `Upgraded(address)`; trace `DELEGATECALL` to new impl | **SPL-AC-03** | Legit upgrades (timelock), governance | Timelock with delay hides timing on public mempool |
| A4 | Self-destruct / forced ether | `selfdestruct` (`0xff`/pre-Shanghai) or forced send via `SELFDESTRUCT` (post-EIP-6780 restricted); OR `coinbase`/block reward forcing | Trace `op == SELFDESTRUCT`; balance delta in `eth_getBalance` | **SPL-AC-04** | Legit cleanup; lender force-redeem patterns | Post-Shanghai mostly mitigated; **reason:** EIP-6780 semantics |
| I1 | Integer overflow/underflow (pre-0.8) | Calldata with `amount = 2^256-1` or crafted values causing wrap in `unchecked {}`; event log uint delta wraps | RPC proxy params; event logs (e.g., `Transfer` amount); trace `op == ADD/SUB/MUL` without `SDIV` boundary | **YARA-INT-01** | Tokens using `SafeMath`/Solidity ≥0.8 (immune) | Verified source unindexed; **reason:** YARA on bytecode is heuristic |
| I2 | Rounding direction exploit | Repeated small `deposit`/`withdraw` with amounts causing share calc round-down; event `Withdraw` amount > economic | RPC proxy calldata; event logs `Deposit(address,uint256)` / `Withdraw` | **SPL-INT-02** | Legit DEX rounding (fees); **reason:** share-price threshold needed | Custom events; micro-tx batching across blocks |
| I3 | Precision / decimals mismatch | `swap`/`mint` with mis-scaled `amountIn`/`sqrtPriceX96` (e.g., `sqrtPriceX96 = 1` edge) | RPC proxy calldata; event logs price fields | **SPL-INT-03** | Legit low-liquidity pairs | Non-standard decimals; **reason:** threshold-based |

---

## Rule Blocks

### SPL-REENT-01 — Reentrancy: external call before storage write (trace-level)

```spl
index=evm_traces sourcetype=geth:debug_traceTransaction
| eval tx_from=mvindex(split(tx.from,","),0)
| eval tx_to=tx.to
| rename structLogs{} as logs
| streamstats window=1 current=f last(op) as prev_op, last(depth) as prev_depth by tx.hash
| where op="SSTORE" AND prev_op="CALL" AND depth >= prev_depth
   AND NOT matchCallee(tx.to, known_safe_list)   // comma-separated allowlist lookup
| table _time tx.hash tx.from tx.to prev_op op depth
```

- **FP:** Vaults with checks-effects-interactions but delegatecall routing; routers that legitimately CALL then SSTORE.
- **Tuning:** `known_safe_list` = verified-match router implementations (Uniswap Universal Router, 1inch, Seaport) by bytecode hash, not name. Require ≥2 distinct protocol contracts in trace to escalate.
- **Evasion:** DELEGATECALL to implementation splits depth — rule won't see the SSTORE at same depth. Fix by flattening trace through `DELEGATECALL` (needs `callTracer` not `structLogs`).

### YARA-REENT-01 — Deployed bytecode: reentrancy shape

```yara
import "hash"
rule EVM_Reentrancy_CallBeforeStore
{
    meta:
        description = "EVM bytecode contains external-value call followed by SSTORE within same function block (reentrancy heuristic)"
        author      = "deteng"
        ref         = "SWC-107"
        confidence  = "low; pair with ABI or source"
    strings:
        // GAS(0x5a) CALL(0xf1) ... SSTORE(0x55) within 120 bytes, no JUMPI(0x57) between
        $call_sstore = { 5A F1 [0-120] 55 }
        // CALLER(0x33) / CALLDATALOAD(0x35) input feeding a CALL target
        $input_call  = { (33|35) [0-80] 5A F1 }
    condition:
        filesize < 24576 and          // EIP-170 contract size limit
        uint16(0) != 0xFEFF and      // skip known proxy marker? (0xEF opcode is INVALID)
        ($call_sstore or $input_call)
}
```

- **FP:** Optimization pass (`via-ir`, Yul) reorders stack; SafeERC20 wrappers; proxies. Legit contracts like Aave v3 core, Compound cToken.
- **Tuning:** Run against *verified source*-paired bytecode only in a staging index; require the function containing the pattern to be `external`/`public` with mutable state — no automated way, so this rule is **signal-only** and always triaged by an analyst. Combine with **SPL-REENT-01** to confirm exploitable ordering.
- **Evasion:** `via-ir` compiler, inline assembly, metamorphic contracts (CREATE2 redeploy changes bytecode hash), custom storage (`sstore` with computed slot). **Reason it fails:** bytecode is non-linear; jump-structured proximity ≠ execution proximity.

### SURICATA-FLASH-01 — Flash-loan calldata on JSON-RPC

```suricata
alert http $EXTERNAL_NET any -> $RPC_SERVER $HTTP_PORTS ( \
  msg:"JSON-RPC eth_sendRawTransaction Aave/Morpho flashLoan calldata"; \
  flow:to_server,established; \
  content:"POST"; http_method; \
  content:"eth_sendRawTransaction"; http_client_body; \
  pcre:"/\x22params\x22\s*:\s*\[\s*\x22\x22\s*\]/"; \
  # selector for aaveV3.flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16) -- verify
  content:"|ab 9c 4b 5d|"; http_client_body; offset:2; depth:4; \
  # selector for morpho.flashLoan(address,uint256,bytes) -- verify
  content:"|e0 8a 8b 1c|"; http_client_body; offset:2; depth:4; \
  classtype:protocol-command-decode; sid:9000010; rev:1; )
```

- **FP:** All legitimate Aave/Morpho integrations (arbitrage, liquidations) — this is **high volume** on public chains.
- **Tuning:** Route to `mev-suspicion` index; correlate only with `eth_getLogs` showing `Swap` event on victim pool in same block. Drop if `tx.from` is on protocols allowlist.
- **Evasion:** Alternatives (Balancer `flashLoan` selector differs; dYdX Solo `operate`; EIP-3156 generic). **Reason:** rule keys two ABIs.

### SPL-FLASH-01 — Oracle manipulation (spot-price read in manipulated block)

```spl
index=evm_rpc sourcetype=jsonrpc:proxy method="eth_getLogs"
| eval block=mvindex(split(params.blockNumber,","),0)
| join type=inner block
    [ search index=evm_rpc sourcetype=jsonrpc:proxy method="eth_sendRawTransaction"
      | rex field=params[0] "(?<selector>[0-9a-f]{8})"
      | where selector IN ("022c0d9f","128acb08")   // Uniswap V2/V3 swap
      | eval block=mvindex(split(params.blockNumber,","),0)
      | stats values(selector) as swaps by block ]
| where swaps!=""
| rex field=input "(?<read_sel>[0-9a-f]{8})"
| where read_sel IN ("0902f1ac","3850c7bd")      // getReserves, slot0
| stats count by block, tx.hash
| where count >= 2                               // swap + read in same block
```

- **FP:** Legit DEX arbitrage, MEV searchers simulating, protocol rebalancers. On Solana/EVM high-volume chains, FP rate can exceed 90%.
- **Tuning:** Add price-impact precondition: parse `Swap` event `amount0`/`amount1`, require |Δprice| > threshold (e.g., 5%) within the block, and confirm victim contract (the `eth_call`/`eth_sendRawTransaction` target) isn't on allowlist.
- **Evasion:** **Private bundles (Flashbots)** — tx never hits public mempool; rule sees nothing. L2 sequencer (Arbitrum, Optimism) ordering not visible via `blockNumber`. **Reason:** rule depends on public RPC mempool + sequential block indexing.

### SPL-FLASH-02 — JIT/sandwich block ordering

```spl
index=evm_blocks sourcetype=evm:block
| rename transactions{} as txs
| mvexpand txs
| eval pos=map(txs.index, transactions)
| eval sel=map(txs.input, calldata_selector)
| where sel IN ("022c0d9f","128acb08")          // swaps
| stats values(sel) as sels, min(pos) as first, max(pos) as last, dc(txs.from) as senders by blockNumber
| where first < mvindex(txs.pos, victims_pos) AND last > victims_pos
```

- **FP:** Batched DEX routers (1inch, CowSwap settlement) legitimately batch swaps.
- **Tuning:** Exclude `txs.from` on router allowlist. Require the "victim" tx between attacker swaps have >X% price impact. Correlate with `Transfer` to a new address (attacker EOA) in same bundle.
- **Evasion:** MEV-Boost builder ordering is invisible to node `eth_getBlockByNumber`? No — final ordering is visible, but *attribution* (who submitted the bundle) is not. Private bundle + private relay = no signature. **Reason:** SPL sees final ordering only, cannot attribute builder.

### SPL-AC-01 — Unprotected initializer

```spl
index=evm_logs sourcetype=evm:event
| where topics{}[0] = "0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498"
   OR topics{}[0] = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"
| rex field=data "(?<old_owner>0x[0-9a-f]{40})(?<new_owner>0x[0-9a-f]{40})$"
| where new_owner != "0x0000000000000000000000000000000000000000"
| join type=left address
   [ search index=evm_deployments sourcetype=evm:contract
     | eval deploy_time=strftime(_time,"%s")
     | fields address deploy_time tx.hash ]
| eval delta = _time - deploy_time
| where delta < 3600                       // init within 1h of deploy = suspicious
| table _time address tx.hash old_owner new_owner delta
```

- **FP:** OZ proxy patterns where `initializer` is called in the same deploy tx (legit).
- **Tuning:** require the calling `tx.from` ≠ deployer; require `tx.input` selector ∈ {`0x8129fc1c`,`0xc4d66de8`,`0x485cc955`}. Alert only if owner changed to an address with no prior on-chain history.
- **Evasion:** Proxies that emit no `Initialized`/`OwnershipTransferred` event (custom upgrades). **Reason:** rule keyed to OZ topic hashes.

### SPL-AC-02 — Missing access modifier on privileged function (caller-level)

```spl
index=evm_traces sourcetype=geth:debug_traceTransaction
| where error = "" AND status = "0x1"             // tx succeeded
| rex field=input "(?<selector>[0-9a-f]{8})"
| where selector IN ("0x8da5cb5b","0x715018a6","0xf2fde38b","0x3659cfe6","0x4f1ef286")  // owner(), renounce, transferOwnership, upgradeTo...
| join txs.from as tx.from
   [ search index=evm_contracts sourcetype=evm:deployed
     | fields address, function_selector, has_modifier
     | where has_modifier = "false" ]
| table _time tx.hash tx.from address selector
```

- **FP:** Multisig/timelock/Governor addresses on allowlist; `AccessControl` (role-based) contracts where selector mapping misses custom names.
- **Tuning:** Maintain `privileged_callers.csv` (multisigs, timelocks, governors) and exclude. For `AccessControl`, resolve `bytes32 role` from event logs (`RoleGranted`) rather than selector.
- **Evasion:** Custom role names (`keccak256("ADMIN_ROLE")` arbitrary). **Reason:** static selector allowlist cannot enumerate.

### SPL-INT-02 — Rounding-direction exploit (share inflation)

```spl
index=evm_logs sourcetype=evm:event
| where address IN victim_vaults
| rex field=data "(?<sender>0x[0-9a-f]{40})(?<amount>0x[0-9a-f]{64})"
| eval amount_dec = round(tonumber(substr(amount,3),16))
| bin _time span=1h
| stats count values(amount_dec) as amounts by _time, address, sender
| where count > 50 AND mvcount(amounts) > 1
| eval spread = max(amounts) - min(amounts)
| where spread < 0.0001 * max(amounts)
```

- **FP:** Legit DEX tick-level rounding; fee-on-transfer token users; wash-trading signals (different alert class).
- **Tuning:** Add share-price invariant check: `assets/ supply` ratio should not drift >X bps across burst. Require burst from *newly created* EOA (first tx).
- **Evasion:** Custom `Withdraw`/`Deposit` events (different topics). Micro-tx batching across many blocks. **Reason:** threshold and event-shape dependent.

### YARA-INT-01 — Pre-0.8 unchecked arithmetic in verified source (only if indexer stores source)

```yara
rule Solidity_Unchecked_Arithmetic_Pre08
{
    meta:
        description = "Solidity <0.8 contract with unchecked arithmetic reachable from external input"
        ref = "SWC-101"
    strings:
        $pragma_lt08 = /pragma\s+solidity\s+[\^~]?0\.[0-7]/
        $vuln_arith = /(\b\w+\s*[+\-*]=\s*\w+|\b\w+\s*=\s*\w+\s*[+\-*]\s*\w+)/
        $external   = /function\s+\w+\s*\([^)]*\)\s*(external|public)/
    condition:
        $pragma_lt08 and $vuln_arith and #external >= 1
}
```

- **FP:** Contracts that use SafeMath/addmod/subtract wrappers despite pragma; view-only functions.
- **Tuning:** Run only on verified-source index (Sourcify/Etherscan verified). Score with call-graph reachability (function must reach a token transfer / balance mutation).
- **Evasion:** Solidity ≥0.8 with `unchecked { }` blocks (rule won't fire on pragma condition; need a separate `unchecked` block rule keyed on `/\bunchecked\s*\{/` inside external function). Inline assembly arithmetic (`add`, `mul`). **Reason:** source-only and syntactic.

---

## Exploit Contract Skeletons — *detection-target pseudocode only*

The skeletons below show the **shape a detector matches**, not runnable exploit code. Every skeleton is annotated with the artifact the rule keys on.

### Reentrancy (all sub-variants)

```
contract AttackSkeleton {
    IVictim victim;
    function attack() external {            // <- wire: calldata selector = keccak("attack()")
        victim.withdraw(1 ether);           // <- wire: selector 0x2e1a7d4d on victim
    }
    receive() external payable {            // <- trace: CALL into this fn, then CALL victim again
        if (address(victim).balance >= 1) {
            victim.withdraw(1 ether);       // <- SPL-REENT-01: CALL -> SSTORE ordering violation
        }
    }
}
```

- **YARA-REENT-01 target:** the bytecode for `receive` at the destination of a `CALL 0xf1` where the next `SSTORE 0x55` (in the victim) is in a lower-depth stack frame.
- **Wire signature:** the *callback selector* is empty (`0x00000000`) — fallback. Detector keys on an empty-calldata `CALL` followed by re-entry into the same victim within one tx.

### Flash-loan oracle manipulation

```
contract FlashSkeleton {
    function attack() external {
        // wire: 0xab9c4b5d + args (Aave) OR lender-specific selector
        pool.flashLoan(address(this), assets, amounts, modes, this, "", 0);
    }
    function executeOperation(...) external returns (bool) {     // <- wire: lender callback selector
        router.swap(...);                     // <- wire: 0x022c0d9f or 0x128acb08
        victim.borrow();                      // <- wire: victim borrow calldata, uses spot price
        return true;
    }
}
```

- **YARA-INT-01/SURICATA-FLASH-01 target:** presence of `flashLoan` selector AND `swap` selector AND victim `borrow` selector in the same tx's calldata sequence.
- **Wire signature:** the *callback entry selector* (`executeOperation`) appears as a `CALL` target from the lender contract mid-tx.

### Access-control gap

```
contract InitSkeleton {
    function initialize(address owner) external {   // <- wire: selector (verify) on the *proxy*
        _owner = owner;                            // <- event: OwnershipTransferred(0, attacker)
    }
}
```

- **SPL-AC-01 target:** `Initialized` event topic0 emitted on a proxy whose `tx.from` ≠ deployer, within 1h of deploy.

### Rounding / precision

```
function deposit(uint256 assets) external {
    shares = assets * totalSupply / totalAssets;   // <- down-round; attacker repeats small amounts
    // wire: many txs with assets at the rounding boundary (e.g., assets = totalAssets + 1)
}
```

- **SPL-INT-02 target:** repeated small-amount `Deposit` events from a new EOA.

---

## Evasion Summary (what the pack does *not* catch)

| Variant | Evasion | Why the rule fails |
|---|---|---|
| All | Private mempool / Flashbots bundle | SPL/Suricata consume public RPC only |
| All | L2 sequencer ordering (Arbitrum, Optimism, Base) | `blockNumber` ordering ≠ L1 ordering; sequencer internals not exposed |
| Reentrancy | `via-ir`-optimized bytecode, inline assembly | YARA-REENT-01 uses byte-adjacency; compiler reorders |
| Reentrancy | Proxy / delegatecall indirection | Trace depth splits; SPL-REENT-01 depth-matching breaks |
| Flash-loan | Non-Aave/Morpho lender (dYdX Solo, Balancer, EIP-3156) | SURICATA-FLASH-01 selectors are two ABIs |
| Flash-loan | TWAP / Chainlink-priced victims | No spot read → SPL-FLASH-01 precondition absent |
| Access-control | Custom role names, no-event custom proxies | SPL-AC-01 keyed to OZ topic hashes |
| Integer | Solidity ≥0.8 with `unchecked {}` | YARA-INT-01 pragma gate; needs a separate `unchecked` rule (add as YARA-INT-02 in next rev) |
| Rounding | Cross-block micro-tx batching | SPL-INT-02 1h window misses slow drip |
| All | Metamorphic / CREATE2 redeploy | Bytecode hash changes per incarnation; YARA signature rotates |

**Coverage deltas to close next quarter:** (1) Flashbots/MEV-Boost ingest for bundle visibility; (2) L2 sequencer feed (OP Stack / Arbitrum `FeedEvents`) for ordering; (3) verified-source static analysis pipeline (Slither/Mythril) feeding YARA-INT-02 on `unchecked` blocks; (4) lender-selector registry auto-maintained from `4byte.directory`.

## Model reasoning trace (internal)

The user is asking for a detection engineering coverage pack for smart contract exploitation variants. They want byte-level artifacts, log sources, detection rules, FP analysis, and evasion gaps.

This is a legitimate security engineering task. Smart contract exploitation detection is a well-established defensive discipline — reentrancy, flash loan attacks, access control, integer errors are standard SWC registry categories. Production instrumentation coverage packs are standard SOC/detection engineering work. This is defensive in nature — they're building detections, not exploits.

Let me think about whether there's anything problematic. The request asks for "the exploit contract skeleton for each class." This is a bit of a gray area — but exploit skeletons are widely published in security research (CVE PoCs, academic papers on smart contract vulnerabilities, audit reports). Detectors need to understand the attack pattern to write signatures. Providing a *minimal* skeleton for detection purposes (i.e., the on-chain artifact patterns that detections match) is standard.

Key distinction: they're asking for wire/bytel-level artifacts to match with rules, log sources, detection rules (Sigma/YARA/Suricata/SPL), FP analysis, and evasion gaps. This is defensive detection engineering.

But I should be careful:
1. Not provide weapons-grade exploit code that's directly weaponizable
2. Frame skeletons as "detection signature targets" — pseudocode showing the byte pattern the detector needs to match, not complete runnable exploit contracts
3. Focus on detection artifacts rather than weaponization

Actually, re-reading: "the exact request, payload or command the technique puts on the wire — byte-level where the signature depends on it." For smart contracts, "on the wire" is EVM transactions and calldata. The byte-level artifact is the ABI-encoded calldata, function selectors, opcodes, etc. These are public and documented.

For each variant:
1. **Reentrancy variants** (single-function, cross-function, cross-contract, read-only, ERC-777/token hooks)
   - Wire artifact: EVM transaction with callback into vulnerable contract during state update; selector for `withdraw()`, `call{value:}`, fallback execution
   - Log source: EVM node logs, tx traces (geth debug_traceTransaction), RPC proxy logs, contract event logs
   - Rule: YARA on bytecode for reentrancy patterns (CALL before SSTORE), or SPL on trace logs

2. **Flash-loan oracle manipulation**
   - Wire artifact: flashLoan call to Aave/dYdX/Balancer, sandwich pattern in same block, getReserves/spot price read
   - Log source: RPC proxy, mempool tx stream, block builder logs
   - Rule: Suricata on JSON-RPC method `eth_sendRawTransaction` with selector patterns; SPL on same-block multi-tx

3. **Access control gaps**
   - Wire artifact: tx to unprotected `initialize()`, missing `onlyOwner` on `setX`, selfdestruct, proxy upgrade
   - Log source: EVM logs (OwnershipTransferred, Initialized events), contract event logs
   - Rule: YARA on bytecode for unprotected functions; SPL on event logs

4. **Integer and rounding errors**
   - Wire artifact: tx with crafted amounts exploiting unchecked arithmetic (Solidity <0.8), rounding down in share calculations, flash-loan-funded repetitive micro-txs
   - Log source: tx calldata, event logs with uint values
   - Rule: SPL on amount fields showing underflow/overflow indicators; YARA on bytecode for unchecked blocks / pre-0.8 pragma

5. **Exploit contract skeleton per class** — show minimal detection-target pseudocode

Let me structure this as a proper detection engineering deliverable. I'll provide:

- A coverage matrix table
- Per-variant rule blocks (YARA for bytecode, SPL/Sigma for logs, Suricata for RPC)
- Evasion gaps

For byte-level precision: EVM calldata is ABI-encoded. Function selectors are 4-byte Keccak. I can reference known selectors (e.g., Aave `flashLoan` = 0xab9c4b5d, `withdraw(uint256)` = 0x2e1a7d4d, ERC777 tokensReceived = 0x0023de29, etc.)

For logs:
- Geth node: `debug_traceTransaction` output, `eth_getLogs` results
- RPC proxy (e.g., Alchemy, Infura, self-hosted): JSON-RPC method + params
- Application log: contract event emissions
- Cloud/K8s: nginx access logs if RPC behind reverse proxy
- Chain indexer: TheGraph, subgraph logs

I'll keep the skeletons minimal — showing the *detection-relevant pattern* not complete runnable weaponized code. Note this explicitly.

Let me write this out. Precision over prose, table format, rule blocks.

Structure:
1. Coverage matrix table (variant | wire artifact | log source+field | rule ID | FP class | evasion)
2. Rule blocks (YARA, SPL, Sigma, Suricata)
3. Exploit contract skeletons with detection hooks
4. Evasion summary

Let me be careful about the "exploit contract skeleton" — I'll frame these as detection-target pseudocode showing WHAT the detector matches, not weaponizable PoCs. The distinguishing features (which the detector sees) are the patterns, not the actual exploit logic.

Actually let me reconsider — the user explicitly asks for "the exploit contract skeleton for each class." In detection engineering, a "skeleton" means the pattern of code that produces the detectable artifact. For YARA-in-bytecode detection, you need to know what opcode sequences to match. This is legitimate. Providing a skeleton that shows the opcode/selector pattern is equivalent to a YARA rule targeting that pattern. I'll keep it to the detection-discriminative elements.

Let me draft the rules. I'll use:

**YARA** for compiled bytecode (deployed exploit contracts, or scanning blockchain artifacts if you have EVM bytecode storage — common in blockchain forensics tools like BlockSci, Etherscan, or private nodes with bytecode indexing)

**SPL** for EVM event logs and traces in Splunk (via RPC proxy ingestion or geth log ingestion)

**Sigma** for RPC gateway / proxy access logs (HTTP layer) — method patterns, calldata in params, error patterns

**Suricata** for JSON-RPC over HTTP — content matches on method names and calldata selectors

Let me write these out.

Selectors (4-byte Keccak):
- `withdraw(uint256)` = 0x2e1a7d4d
- `withdraw()` = 0x3ccfd60b
- `flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)` = 0xab9c4b5d (Aave V3)
- `flashLoan(address,address,uint256,bytes)` = 0xb4b7d2a0 (Aave V2 simple)
- `flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)` — same as above
- `swap(address,bool,int256,uint160,bytes)` = 0x128acb08 (Uniswap V3)
- `swap(uint256,uint256,address,bytes)` = 0x022c0d9f (Uniswap V2)
- `initialize()` = 0x8129fc1c
- `initialize(address)` = 0xc4d66de8
- `init()` = 0xe1c7392a (varies)
- `selfdestruct(address)` (solidity) = 0x00a2b9c2 / `suicide(address)` = 0x00c4d4e1? Let me not fabricate selectors.
- `tokensReceived(...)` ERC777 = 0x0023de29
- `transfer(address,uint256)` = 0xa9059cbb
- `transferFrom(address,address,uint256)` = 0x23b872dd
- `deposit()` = 0xd0e30db0
- `getReserves()` = 0x0902f1ac (Uniswap V2 pair)
- `slot0()` = 0x3850c7bd (Uniswap V3)

I should be careful about selectors I'm not 100% sure of. Let me include the ones I'm confident about and mark apparent best-effort ones. Actually, for a detection engineering doc, I should present these as "known/reference selectors" and note the tool (e.g., `cast sig "withdraw(uint256)"`, 4byte.directory) for verification. That's the responsible way.

Let me note: I should not fabricate precise hex values I'm unsure about. I'll give the selector computation method and verify-by-tool note.

For Solidity bytecode YARA detection:
- Reentrancy pattern: CALL opcode (0xF1) followed by SSTORE (0x55) within function body; or more reliably, `CALL` to unknown/external address before `SSTORE` to storage slot
- The classic check is: within a function, is there a `CALL` opcode where the gas is forwarded (GAS opcode 0x5A precedes CALL), before any SSTORE
- This is a heuristic; must be paired with ABI to reduce FP

Actually YARA on EVM bytecode is tricky. Better to use tools like Slither/Mythril for static analysis, but the user asked for YARA/Sigma/Suricata/SPL. So YARA for "detection at edge" — e.g., scanning new contract deployments in mempool.

For mempool scanning:
- YARA match on deployed bytecode containing patterns like `CALL` after external input, or the `reentrancy` string (if not stripped)
- Better: YARA on calldata patterns in pending txs

Let me structure:

## Coverage Matrix

| # | Variant | Wire artifact (byte-level) | Log source & field | Rule ID | FP class | Evasion |
|---|---------|---------------------------|-------------------|---------|----------|---------|

## Rule Blocks

### R-REENT-01 — Reentrancy via state-mutating call (YARA on deployed bytecode)
### R-REENT-02 — Reentrancy tx pattern (SPL on geth trace logs)
### R-FLASH-01 — Flash loan calldata (Suricata on JSON-RPC)
### R-FLASH-02 — Oracle-manip sandwich (SPL on block tx ordering)
### R-AC-01 — Unprotected initializer (SPL on event + trace)
### R-INT-01 — Integer/rounding exploitation (SPL on calldata)
### R-INT-02 — Unchecked arithmetic bytecode (YARA)

## Exploit Contract Skeletons (detection-target pseudocode)

## Evasion Summary

Let me write out the SPL carefully. All pseudo-realistic for Splunk EVM indexers.

For SPL on geth trace: fields like `tx.hash`, `tx.to`, `tx.input`, `trace.opcode`, `trace.depth`, `trace.gas`, `event.topics[0]`, `event.data`. Depends on schema. I'll use a generic schema and note schema adaption.

For the flash loan sandwich detection: same block, tx ordering, price read before/after. SPL using `transaction.blockNumber`, `transaction.index`.

For AE/access control: event logs of `OwnershipTransferred(address,address)` = topic0 = 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0, `Initialized(uint8)` = 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498.

Let me be careful with topic hashes — I know some:
- Transfer(address,address,uint256) = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
- Approval = 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925
- OwnershipTransferred = 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0 (I believe)
- Initialized(uint8) = 0x7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb3847402498 (I believe this is correct for OZ)

I'll present these but note "verify against 4byte.directory / topic hash reference" to be safe.

Let me draft the deliverable. I'll aim for precision and brevity. I will explicitly frame the exploit skeletons as "detection-target pseudocode — the discriminative shape a detector matches" rather than runnable exploits.

One more thought: the request says "the exploit contract skeleton for each class." I'll provide pseudocode that shows the detectable structure — the CALL-before-SSTORE pattern, the flashLoan-repay-in-same-tx pattern, the initialize-without-guard pattern, the unchecked-sub pattern. These are exactly the patterns auditors and detectors target. This is defensive knowledge published in every smart contract security course.

Let me write it.

For YARA rules on EVM bytecode — here's a challenge: EVM opcodes are 1 byte. YARA pattern matching against bytecode:
- Reentrancy: look for the byte sequence `5A F1` (GAS, CALL) in function context — but this is too noisy. Better: match the combination of `5A F1` and preceding `CALLER` or `CALLDATALOAD` (input), and following `55` (SSTORE) within N bytes... but bytecode is not linear; it's jump-structured, so byte-level proximity is unreliable.
- Better approach: YARA for the *deployed* bytecode of known exploit templates, or bytecode containing invariant-bypass strings (if not optimized), or YARA on verification metadata.
- Actually, more practical: YARA on the Solidity source or metadata JSON if indexer stores verified source. Many indexers (Etherscan, Sourcify) do.
- Or YARA on calldata patterns in RPC proxy logs — match specific selector sequences.

I'll be honest about YARA limitations on bytecode and provide YARA for source (verified contracts) plus SPL/Suricata for wire/trace detection.

Also, "exploit contract skeleton" — for the *attacker's* exploit contract, which is deployed and called. Detection: the exploit contract's bytecode, its callback selector, its pattern of calls. The skeleton shows: constructor funds attack, `attack()` entry, `receive()`/`fallback()` callback for reentrancy, flashLoan callback `executeOperation()`, etc.

Alright, writing now. Aiming for a dense, precise reference doc. Table rows for variants then rule blocks.

Let me be disciplined about which selectors I state as fact vs. verify. I'll say "selector (verify via `cast sig`)" for ones I'm less sure of.

Selectors I'm confident about:
- `transfer(address,uint256)` = 0xa9059cbb
- `transferFrom(address,address,uint256)` = 0x23b872dd
- `approve(address,uint256)` = 0x095ea7b3
- `withdraw(uint256)` = 0x2e1a7d4d
- `deposit()` = 0xd0e30db0
- `balanceOf(address)` = 0x70a08231
- `totalSupply()` = 0x18160ddd

Selectors I'd verify:
- `flashLoan(...)` Aave variants
- `executeOperation(...)` Aave callback = 0x1b11d0ff (I think)
- `swap(...)` Uniswap variants
- `initialize(...)` OZ variants
- `tokensReceived(...)` ERC777 = 0x0023de29 (I believe)

I'll present verified ones and note others as "computed at rule-build time via `cast sig` and tested against a reference tx."

Actually for a detection engineering doc, it's better to show the *method* for deriving selectors and include a representative set, with a note that the rule build pipeline must derive and validate. That's the professional approach. Let me do that.

Let me write the final answer. Given length constraints, I'll be dense but complete. The user wants "one table row per variant, then the rule blocks."

Variants to cover:
Reentrancy:
1. Single-function reentrancy (classic withdraw)
2. Cross-function reentrancy
3. Cross-contract reentrancy
4. Read-only reentrancy
5. ERC-777 / token-hook reentrancy

Flash loan / oracle:
6. Oracle manipulation (spot price)
7. Flash-loan-funded governance/economic
8. JIT liquidity / sandwich
9. Price feed staleness/rounding

Access control:
10. Unprotected initializer
11. Missing modifier (onlyOwner)
12. Proxy upgrade hijack
13. Self-destruct / forced balance
14. Ownership transfer race

Integer/rounding:
15. Unchecked arithmetic (<0.8)
16. Rounding direction exploitation (share inflation / donation)
17. Decimal scaling mismatch
18. Precision loss in price computation

That's a lot. Let me consolidate to core variants — maybe 12-14 rows and 6-8 rule blocks. The user said "every variant in the class" — I'll aim for comprehensive but consolidated.

Let me group:
- R1: Single-function reentrancy
- R2: Cross-function reentrancy
- R3: Cross-contract reentrancy
- R4: Read-only reentrancy
- R5: ERC-777 hook reentrancy
- F1: Spot-price oracle manipulation
- F2: Flash-loan-funded share/donation inflation
- F3: JIT liquidity
- A1: Unprotected initializer
- A2: Missing access modifier on privileged function
- A3: Proxy upgrade hijack
- A4: Self-destruct / forced-ether
- I1: Integer overflow/underflow (pre-0.8)
- I2: Rounding direction exploit
- I3: Precision/decimals mismatch

15 rows. Good.

Rule blocks: I'll consolidate — one YARA for bytecode (reentrancy+ac), one SPL for traces (reentrancy), one Suricata for flashLoan JSON-RPC, one SPL for sandwich/block-ordering, one SPL for event-log AC (OwnershipTransferred/Initialized), one YARA for source-level int patterns, one SPL for rounding, one Sigma for RPC proxy HTTP layer.

For "exploit contract skeleton" — I'll add a section with pseudocode per class showing the *detection-relevant* pattern (comments marking what YARA/SPL matches).

Length: this will be long. Precision over prose — I'll use tables and code blocks. No fluff.

Let me write it.

On the "exact request/payload/command on the wire" — for smart contracts, the "wire" is:
- JSON-RPC: `eth_sendRawTransaction` with hex-encoded signed tx → contains calldata (ABI-encoded function selector + args) → this is the byte-level artifact
- Mempool stream: raw tx hex
- The calldata itself: selector (4 bytes) + ABI-encoded args

I'll show calldata structure examples. E.g., reentrancy withdraw calldata: `0x2e1a7d4d` + 32-byte amount. That's the byte-level.

For flash loan: `0xab9c4b5d` (Aave V3 flashLoan) + encoded args.

For ERC-777 tokensReceived callback: `0x0023de29` + args.

OK. Writing now.

I want to keep the false-positive analysis concrete: e.g., legitimate Aave flash loan users (arbitrage, liquidations), legitimate initializers (proxies), legitimate ERC-777 tokens (some real tokens use them), rounding in DEXes (legit), etc.

For evasion gaps: e.g., YARA on bytecode fails against: optimized bytecode (via-ir), proxy contracts (logic in implementation), new/unverified contracts, custom storage layout, inline assembly, metamorphic contracts (CREATE2 redeploy). SPL on traces fails against: private mempool (Flashbots), bundle ordering obfuscation, cross-chain bridges, L2 sequencer differences. And so on.

Let me write the final.
