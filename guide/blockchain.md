---
icon: hive
---

# Blockchain

## ⛓️ **Blockchain for CTFs — Smart Contracts, Chains, and Crypto Exploits**

> _“Blockchains don’t forget. But they do make mistakes.”_\
> Blockchain CTFs test your understanding of decentralized logic, transaction flow, and how **smart contract misconfigurations** lead to compromise — ethically and academically.

***

### I. 🧩 **Core Concepts Recap**

| Concept                                | Description                                                            |
| -------------------------------------- | ---------------------------------------------------------------------- |
| **Blockchain**                         | A distributed ledger of immutable transactions.                        |
| **Block**                              | Contains transactions + previous hash + nonce.                         |
| **Wallet / Address**                   | Public/private key pair controlling funds.                             |
| **Transaction (TX)**                   | Signed data that changes blockchain state.                             |
| **Smart Contract**                     | Code deployed on a blockchain (e.g., Ethereum) executing autonomously. |
| **Gas**                                | Unit of computation cost in Ethereum.                                  |
| **ABI (Application Binary Interface)** | Interface describing how to interact with contract functions.          |
| **Bytecode / EVM**                     | Low-level opcodes executed by Ethereum Virtual Machine.                |

***

### II. ⚙️ **Common Platforms & Testnets in CTFs**

| Platform                                      | Description                              |
| --------------------------------------------- | ---------------------------------------- |
| **Ethereum / Solidity**                       | Most CTF tasks use this stack.           |
| **Binance Smart Chain**                       | EVM-compatible — same logic applies.     |
| **Hyperledger / EOS / Tron**                  | Rare, but occasionally appear.           |
| **Remix IDE / Ganache**                       | Local test networks for experimentation. |
| **Ethernaut / Damn Vulnerable DeFi (D.V.D.)** | Interactive CTF training frameworks.     |

***

### III. 🔬 **Blockchain Reconnaissance in CTFs**

#### 1️⃣ Inspect the Challenge

* You’ll often get:
  * **Contract address** (on testnet)
  * **Source code** or ABI
  * Sometimes private keys or partial data

#### 2️⃣ Tools to Start With

| Tool                   | Use                                          |
| ---------------------- | -------------------------------------------- |
| `etherscan.io`         | Explore contracts, verify code               |
| `ethervm.io/decompile` | Decompile bytecode                           |
| `remix.ethereum.org`   | Run and interact with contracts              |
| `web3.py` or `Brownie` | Python frameworks for scripting transactions |
| `ganache-cli`          | Local chain for simulating transactions      |
| `mycrypto.com`         | Visual TX crafting                           |

#### 3️⃣ Basic Commands

```bash
# Check contract code
curl https://api.etherscan.io/api?module=contract&action=getsourcecode&address=0x...

# Get ABI
curl https://api.etherscan.io/api?module=contract&action=getabi&address=0x...
```

***

### IV. 🧱 **Smart Contract Vulnerabilities (CTF Edition)**

| Category                          | Description                                            | Example                              |
| --------------------------------- | ------------------------------------------------------ | ------------------------------------ |
| **Reentrancy**                    | Contract calls external function before updating state | `call.value()` before balance update |
| **Integer Overflow/Underflow**    | Arithmetic wraps around                                | `balance -= amount` can overflow     |
| **tx.origin Authentication**      | Using `tx.origin` instead of `msg.sender`              | Attacker tricks original caller      |
| **Delegatecall Injection**        | Logic hijacked via delegatecall to attacker contract   | Storage corruption                   |
| **Unprotected Selfdestruct**      | Anyone can kill contract                               | `selfdestruct(msg.sender)`           |
| **Force Ether Send**              | Contract forced to receive ETH                         | Via `selfdestruct` attack            |
| **Uninitialized Storage Pointer** | Arbitrary memory overwrite                             |                                      |
| **Block.timestamp Dependency**    | Predictable pseudo-random source                       |                                      |
| **Front-running**                 | Public mempool TX reordered by miner                   |                                      |
| **Unsecured Ownership**           | Owner variable not updated / public functions          |                                      |

***

### V. 🧠 **Exploitation Scenarios (Educational)**

#### 1️⃣ **Reentrancy (DAO-style)**

Vulnerable:

```solidity
function withdraw(uint _amount) public {
    require(balance[msg.sender] >= _amount);
    (bool sent, ) = msg.sender.call{value:_amount}("");
    require(sent);
    balance[msg.sender] -= _amount;
}
```

Attacker contract re-calls `withdraw()` before state update.

Defense:

* Use `checks-effects-interactions` pattern.
* Use **ReentrancyGuard** or **mutex**.

***

#### 2️⃣ **Integer Overflow / Underflow**

Vulnerable (pre-Solidity 0.8):

```solidity
balance[msg.sender] -= amount;
```

If `balance = 0`, underflow sets it to `2^256 - amount`.

Defense:

* Use `SafeMath` (now built-in from 0.8+).

***

#### 3️⃣ **tx.origin Trap**

```solidity
require(tx.origin == owner);
```

Attacker makes owner call a malicious contract → passes check.

Defense:

* Always use `msg.sender` for authorization.

***

#### 4️⃣ **Delegatecall Hijack**

```solidity
delegatecall(msg.data);
```

Runs code in another contract **but in the caller’s storage context**.\
CTF exploit: craft malicious delegate contract that overwrites owner variable.

***

#### 5️⃣ **Selfdestruct**

If callable by anyone:

```solidity
function kill() public { selfdestruct(msg.sender); }
```

→ Attacker calls directly, drains contract.

***

### VI. 🧰 **Hands-On Lab Setup**

#### Local Simulation

1️⃣ Install Truffle or Brownie:

```bash
npm install -g truffle
```

2️⃣ Start Ganache testnet:

```bash
ganache-cli -d
```

3️⃣ Load contract in Remix or Truffle console:

```bash
truffle console
> migrate
> contract = await MyContract.deployed()
```

4️⃣ Interact:

```bash
await contract.withdraw({from: attacker, value: web3.utils.toWei("1", "ether")})
```

***

### VII. 🧮 **EVM Opcode Awareness**

| Opcode                 | Function               |
| ---------------------- | ---------------------- |
| `CALL`, `DELEGATECALL` | External calls         |
| `SSTORE`, `SLOAD`      | Storage ops            |
| `SELFDESTRUCT`         | Delete contract        |
| `JUMP`, `JUMPI`        | Control flow           |
| `BALANCE`              | Address balance        |
| `ORIGIN`, `CALLER`     | tx.origin / msg.sender |

Use **ethervm.io** or **evm.codes** to read opcodes directly.

***

### VIII. 💰 **Blockchain Forensics & Analysis**

| Target                 | Tool                                    | Description            |
| ---------------------- | --------------------------------------- | ---------------------- |
| **Transaction Graphs** | `blockchain.com/explorer`               | Track money flow       |
| **Address Clustering** | `walletexplorer.com`, `breadcrumbs.app` | Find connected wallets |
| **Token Transfers**    | `etherscan.io/token`                    | Inspect ERC20 events   |
| **Raw Block Analysis** | `geth`, `jq`, `web3.py`                 | Query blockchain nodes |

***

### IX. 🧠 **CTF Workflow: Blockchain Challenges**

```
1️⃣ Read contract → find vulnerable pattern
2️⃣ Deploy local copy in Ganache or Remix
3️⃣ Write attacker contract or call sequence
4️⃣ Trigger exploit and capture state change
5️⃣ Verify balance / storage manipulation
6️⃣ Extract flag{...} or secret variable
```

***

### X. ⚡ **Common Challenge Patterns**

| Challenge        | Exploit                               |
| ---------------- | ------------------------------------- |
| “Vault” / “Bank” | Reentrancy                            |
| “Coin Flip”      | Predictable RNG using block.timestamp |
| “Delegation”     | Delegatecall hijack                   |
| “Telephone”      | tx.origin misuse                      |
| “Fallback”       | Call to payable fallback drains funds |
| “Preservation”   | Storage collision                     |
| “King of Ether”  | Denial-of-service on reward payout    |

These appear across **Ethernaut**, **Damn Vulnerable DeFi**, **Capture the Ether**, and similar labs.

***

### XI. 🧱 **Security Best Practices**

| Problem                   | Mitigation                                              |
| ------------------------- | ------------------------------------------------------- |
| Reentrancy                | Checks-Effects-Interactions, ReentrancyGuard            |
| Overflow                  | SafeMath / Solidity 0.8+                                |
| Unrestricted Selfdestruct | Restrict to owner                                       |
| Randomness via block      | Use Chainlink VRF                                       |
| tx.origin                 | Replace with msg.sender                                 |
| Delegatecall              | Restrict or remove dynamic calls                        |
| Public variables          | Use private for secrets (though still visible on-chain) |

***

### XII. 🧠 **DeFi & Advanced CTFs**

| Attack Concept          | Description                                       |
| ----------------------- | ------------------------------------------------- |
| **Flash Loans**         | Borrow millions within one TX; manipulate oracles |
| **Oracle Manipulation** | Control data feed → profit via price change       |
| **Front-running**       | Observe mempool → preempt TX                      |
| **Sandwich Attack**     | Insert TXs before and after victim TX             |
| **Governance Attack**   | Gain voting rights, change contract state         |

🧠 These scenarios often appear in **Damn Vulnerable DeFi** or **Paradigm CTF**.

***

### XIII. 🧰 **Block & TX Analysis Commands**

| Command                           | Use                    |
| --------------------------------- | ---------------------- |
| `eth.getTransaction(txHash)`      | Inspect transaction    |
| `eth.getCode(address)`            | Get contract bytecode  |
| `eth.getStorageAt(address, slot)` | Read raw storage       |
| `web3.eth.call()`                 | Query state without TX |
| `truffle decode`                  | Decode event logs      |

***

### XIV. 🧩 **Automation Tools**

| Tool          | Use                                     |
| ------------- | --------------------------------------- |
| **Brownie**   | Python smart contract automation        |
| **Slither**   | Static analyzer for Solidity            |
| **Mythril**   | Symbolic execution vulnerability finder |
| **Echidna**   | Fuzzer for smart contracts              |
| **Manticore** | Binary & EVM symbolic analyzer          |

***

### XV. 🧠 **Quick-Access Cheat Sheet**

| Target                | Command / Concept                        |
| --------------------- | ---------------------------------------- |
| View contract storage | `web3.eth.getStorageAt(addr, slot)`      |
| Decode hex → text     | `web3.utils.hexToAscii("0x666c6167...")` |
| Inspect ABI           | `jq .abi contract.json`                  |
| Test call             | `eth_call` or Remix “Read/Write” tab     |
| Detect vulnerability  | Slither → report summary                 |
| Find selfdestruct     | Search for opcode `0xff`                 |
| Estimate gas          | `web3.eth.estimateGas()`                 |

***

### XVI. 🧠 **Pro Tips**

* Always **recreate the challenge locally** before deploying payloads.
* In multi-contract setups, track **storage slots and addresses**.
* Understand **msg.sender vs tx.origin** — most CTFs hinge on it.
* Use **event logs** to extract hidden info.
* Store decoded data in **CyberChef or Notion** for future mapping.
* Study real CTFs like **Ethernaut**, **Paradigm CTF**, **Damn Vulnerable DeFi** — they teach every pattern.

***
