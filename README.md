# VanityWallet

**Find a wallet address you actually like — hidden inside a seed phrase you already own.**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Offline](https://img.shields.io/badge/network-none-brightgreen.svg)](#security)
[![Spec](https://img.shields.io/badge/BIP--39%20%7C%20BIP--32%20%7C%20SLIP--0010-verified-brightgreen.svg)](#verification)

```
Index         Address
120627        0xcaFE3D…f9B1e7A6
```

---

## Table of contents

- [What it does](#what-it-does)
- [One EVM key covers many chains](#one-evm-key-covers-many-chains)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Backing up a key as a QR code](#backing-up-a-key-as-a-qr-code)
- [Derivation paths](#derivation-paths)
- [How matching works](#how-matching-works)
- [Difficulty and timing](#difficulty-and-timing)
- [Stopping and resuming](#stopping-and-resuming)
- [Seed phrase validation](#seed-phrase-validation)
- [Verification](#verification)
- [FAQ](#faq)
- [Implementation notes](#implementation-notes)

---

## What it does

Your seed phrase doesn't just hold the handful of addresses your wallet shows you. It can generate a huge number of addresses — your wallet only ever displays the first few.

VanityWallet looks through that list for you and tells you which position ("index") produces an address that matches the pattern you want — say, one that starts with `cafe`.

```
seed
 └── one path from your wallet
      ├── index 0        0x9858…   ← what your wallet shows you
      ├── index 1        0x6Fac…
      ├── index 2        0xb671…
      ├──   …
      └── index 120627   0xcaFE…   ← the one you wanted
```

There are over two billion possible addresses on a single path, and VanityWallet doesn't need to check them all — it just searches until it finds one that matches.

**It doesn't create a new wallet or generate new keys.** Every address it finds already belongs to your seed phrase — it was just never shown to you. Your seed phrase already controls it.

Getting to a match depends on how far down the list it is. Wallets add accounts one at a time, so a nearby match takes a few clicks. A distant one, like index 120,627, can't be reached by clicking — instead, you export that specific account's private key from this tool and **import it into your wallet as a separate account**. Every major wallet has an "import account" or "import private key" option for exactly this.

This is different from the usual kind of vanity address tool, which invents a brand new random key with no seed phrase behind it and no way to recover it if you lose that one key.

---

## One EVM key covers many chains

`evm_wallet.py` doesn't produce an "Ethereum key" specifically — it produces an **EVM key**, and that distinction matters.

Ethereum, BNB Chain (BSC), Base, Arbitrum, Optimism, Polygon, Avalanche C-Chain, and most other chains described as "EVM-compatible" all use the exact same address format and the exact same underlying key math. One seed phrase, one derivation path, and one index from this tool produces a single address — and that same address, and the same private key, works unchanged on every chain in that list. There's no separate key to find per chain.

```
Same private key
 ├── Ethereum   → 0xcaFE3D…f9B1e7A6
 ├── BNB Chain  → 0xcaFE3D…f9B1e7A6   (identical address)
 ├── Base       → 0xcaFE3D…f9B1e7A6   (identical address)
 ├── Arbitrum   → 0xcaFE3D…f9B1e7A6   (identical address)
 └── Optimism   → 0xcaFE3D…f9B1e7A6   (identical address)
```

What actually changes between these chains isn't the key or the address — it's:

- **The network your wallet is connected to** (the chain/RPC selector inside MetaMask or whichever wallet you use)
- **The native token you pay gas in** — ETH on Ethereum, Base, Arbitrum, and Optimism; BNB on BNB Chain; MATIC/POL on Polygon; and so on
- **The tokens and contracts that exist on that specific chain** — an address having a balance on Ethereum says nothing about whether it holds anything on Base or Arbitrum; those are separate, unconnected ledgers that just happen to use the same address format

So once you import a private key this tool finds into your wallet, you don't need to search again for BNB Chain, Base, Arbitrum, or Optimism specifically — switching your wallet's network dropdown to any of those shows you that exact same address, ready to receive funds on that chain.

> **This only applies to genuinely EVM-compatible chains.** Bitcoin, Solana, and other non-EVM chains use entirely different address formats and key derivation, so they need their own separate key — that's what `sol_wallet.py` is for. If you're ever unsure whether a chain counts as "EVM-compatible," check whether its addresses look like Ethereum's (`0x` followed by 40 hex characters) — if they do, this same key works there too.

---

## Security

This tool reads your seed phrase, so don't just take our word that it's safe — check for yourself:

```bash
grep -inE "socket|urllib|requests|http|subprocess|eval\(|exec\(|base64|__import__" evm_wallet.py sol_wallet.py
```

That command should print nothing. There's no networking code, no way to send data anywhere, and nothing that runs hidden code. If you want to be extra sure, turn off your Wi-Fi before running it — it works exactly the same with no internet connection.

- You type your seed phrase into the program directly. It's never accepted as a typed command, so it can't end up saved in your shell history.
- Searching only ever prints indexes and addresses. Private keys only show up when you specifically ask to look one up.
- The only file this tool ever writes is the optional match log, and only if you say yes to saving one. It only ever contains addresses, never private keys, and it's saved with permissions that keep it private to you.
- Nothing is ever written to disk or sent over a network by the background search workers.

**Being upfront about limits:** none of this protects you if your computer itself is already compromised. Also, Python can't always fully erase sensitive text from memory once it's been typed, so if that's a serious concern for you, consider running this on a machine with no other software, or one you can wipe afterward. Your seed phrase is shown on screen while you type it, on purpose, so you can double check it's correct — just make sure nobody's looking over your shoulder.

If you do reach a high index and need its private key, treat that private key with the same care as any other: import it straight into your wallet, don't paste it anywhere else, and clear it from your clipboard when you're done. It's worth writing down the derivation path and index somewhere safe too — those aren't sensitive information, but they let you regenerate the same key later if you ever need to.

If this seed phrase protects real funds, it's worth practicing on a spare, empty seed phrase first, then moving funds over once you're comfortable with how the tool works.

---

## Install

There are three files, and each one works completely on its own — copy the one you need and run it. Nothing to build, nothing shared between them.

| File | Chain | Speed (roughly) |
|:--|:--|--:|
| `evm_wallet.py` | Ethereum and other EVM chains | ~16,000 addresses/sec per core |
| `sol_wallet.py` | Solana | ~27,700 addresses/sec per core |
| `qr_backup.py` | Any | turns a seed phrase or private key into a printable QR code |

**You'll need:** Python 3.9 or newer, a terminal, and some free CPU cores — the more you have, the faster the search runs.

### Setting up a clean Python environment

```bash
mkdir -p ~/vanitywallet && cd ~/vanitywallet
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

<details>
<summary>Windows (PowerShell)</summary>

```powershell
mkdir vanitywallet; cd vanitywallet
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```
</details>

Once it's active, your terminal prompt will start with `(.venv)`. Type `deactivate` to leave it, and `cd` back in plus reactivate whenever you want to use it again.

### Installing what you need

Only install the packages for the file you're actually going to run.

**For Solana — `sol_wallet.py`**

```bash
pip install mnemonic solders base58
```

**For Ethereum/EVM — `evm_wallet.py`**

```bash
pip install mnemonic eth-keys eth-utils "eth-hash[pycryptodome]" coincurve
```

`coincurve` isn't required, but without it the tool runs about 50x slower — it'll warn you if it's missing.

**For QR backups — `qr_backup.py`**

```bash
pip install "qrcode[pil]" mnemonic
```

> Keep the quotes around `"eth-hash[pycryptodome]"` and `"qrcode[pil]"` when typing these commands, or the install may fail on macOS.

<details>
<summary><strong>Getting an "externally-managed-environment" error?</strong></summary>

Some systems (Debian, Ubuntu, Fedora, Homebrew Python) won't let you install packages outside of a virtual environment. Just follow the setup steps above and install inside that environment instead — the error can't happen there.

If you really need to install to your system Python anyway:

```bash
pip install --break-system-packages mnemonic solders base58
pip install --break-system-packages mnemonic eth-keys eth-utils "eth-hash[pycryptodome]" coincurve
```
</details>

<details>
<summary><strong>Getting a "Microsoft Visual C++ 14.0 or greater is required" error on Windows?</strong></summary>

That's from `coincurve`, which needs a compiler to install. Either install the Visual Studio Build Tools, or just skip `coincurve` — everything still works, just slower.
</details>

<details>
<summary><strong>Getting an ImportError about eth-hash?</strong></summary>

Reinstall it with the extra included: `pip install "eth-hash[pycryptodome]"`.
</details>

---

## Usage

### Which command to run

Which command works depends on your system, and on whether you're inside the virtual environment from [Install](#install):

- **Inside the activated virtual environment** (what the Install steps above set up) — use `python`. The venv points it at the right Python 3 install on macOS, Linux, and Windows alike, so this one works everywhere once it's active.
- **Outside a virtual environment** — the command differs by OS:
  - **macOS / Linux:** use `python3`. Plain `python` often isn't installed at all, or on older systems points at Python 2.
  - **Windows:** use `python`. The official Windows installer only adds `python.exe`, not `python3.exe`.

Not sure which you have? Run `python3 --version` (macOS/Linux) or `python --version` (Windows) — either should print something starting with `Python 3.`. If it prints `Python 2.x` or errors out, use the other command.

**macOS / Linux**
```bash
python3 evm_wallet.py
python3 sol_wallet.py
```

**Windows (PowerShell or Command Prompt)**
```powershell
python evm_wallet.py
python sol_wallet.py
```

It's menu-driven and will ask you for everything it needs, step by step. Here's what running `evm_wallet.py` looks like (`sol_wallet.py` walks through the same steps, just with Solana's derivation paths and address format):

```
What would you like to do?
  1) Vanity address search
  2) Private key lookup
Choice: 1

Enter seed phrase: <your seed phrase — visible so you can proofread it>
Seed phrase received: 12 words

Select derivation path style:
  1) m/44'/60'/0'/0/i
  2) m/44'/60'/0'/i/0
  3) m/44'/60'/i'/0/0
Choice: 1
Using path: m/44'/60'/0'/0/i

Prefix (blank to skip): cafe
Suffix (blank to skip):
Case sensitive match? (y/N): n
Start index [0]:
End index [100M]:
Save matches to a file? (y/N): n

Search plan
  Path            : m/44'/60'/0'/0/i
  Pattern         : prefix 'cafe' (case-insensitive)
  Index range     : 0 to 100,000,000
  Workers         : 8
  Expected tries  : ~65,536 per match

Index         Address
120627        0xcaFE3D…f9B1e7A6

Summary
  Checked   : 121,600 addresses in 00:00:01 (118,043/s)
  Matches   : 1

To see the private key, run the tool again, choose "Private key lookup",
pick the same derivation path, and enter index 120,627.
```

To actually use a match, run the tool again, choose *Private key lookup*, enter the index it found (like **120627**), and import that private key into your wallet as a new account.

Your seed phrase already controls that address — but wallets normally only check the first few indexes when restoring, so they won't stumble onto index 120,627 on their own. **Write down the derivation path and the index alongside your existing backup.** As long as you have those two things and your seed phrase, that account can always be recovered.

You'll be asked to pick the action and the derivation path every single time you run the tool — there's no default. That's deliberate: picking the wrong path by accident would quietly search a different, unrelated set of addresses, and you wouldn't find out until the address never showed up in your wallet.

**Your seed phrase stays visible while you type it**, so you can double-check every word before continuing. The moment you press Enter, it's cleared from the screen and replaced with just a word count — so if you meant to type 24 words and it shows 12, you'll know right away.

**Both the start and end index you enter are included in the search.** Typing `0` and `100m` searches index 0 through 100,000,000. The largest index this tool can search is 2,147,483,647.

| What you type at the index prompts | What happens |
|:--|:--|
| Nothing, just press Enter | Stops as soon as it finds the **first match** |
| A specific start or end | Searches that **whole range** and reports every match it finds |

---

## Backing up a key as a QR code

`qr_backup.py` turns a seed phrase or private key into a QR code you can print out. It's a separate, optional tool — only use it if you want a paper backup.

Same command rules as above — `python3 qr_backup.py` on macOS/Linux, `python qr_backup.py` on Windows, or just `python qr_backup.py` if you're inside the activated virtual environment.

```bash
python3 qr_backup.py
```

```
What are you encoding?
  1) Seed phrase
  2) Private key
Choice: 2

Enter private key: <visible so you can proofread it>
Private key received: EVM private key (32 bytes, hex)
File name [keys]: keys

Saved  : /your/folder/keys.png
```

Just like the search tools, whatever you type stays visible so you can check it's correct, then disappears from the screen the moment you hit Enter.

- The image is saved in the folder you ran the command from — it can't be saved anywhere else, even if you try.
- It's sized to print cleanly, and uses a high level of error correction, so the code will still scan even if it gets a bit smudged, torn, or damaged.
- Seed phrases are checked for validity before they're turned into a QR code, so you can't accidentally print a typo. Private keys are checked too, and anything that looks unusual asks you to confirm before continuing.
- The file is created with private permissions, and if a file with that name already exists, you'll be asked before it gets overwritten.
- If you have OpenCV installed, the tool scans the saved image back and checks it matches what you typed — it stays quiet if everything checks out, and warns you clearly if it doesn't. Either way, it's worth scanning it with your phone once before relying on it.

> A QR code isn't encrypted — anyone who sees or photographs it can access the wallet. Store the printed copy the same way you'd store your seed phrase, and delete the image file afterward.

---

## Derivation paths

`i` below stands for the index being searched — the number that changes as the tool searches.

**Ethereum / EVM**

| Path | Used by |
|:--|:--|
| `m/44'/60'/0'/0/i` | **MetaMask, Trust Wallet, Phantom** (the most common one) |
| `m/44'/60'/0'/i/0` | less common wallets |
| `m/44'/60'/i'/0/0` | **Ledger Live** |

**Solana**

| Path | Used by |
|:--|:--|
| `m/44'/501'/i'/0'` | **Phantom** (default) |
| `m/44'/501'/0'/i'` | some `solana-cli` setups |

> ### Check your path using index 1, not index 0
>
> Every path above produces the exact same address at index 0 — so checking index 0 won't tell you which path your wallet actually uses.
>
> Instead: run *Private key lookup*, enter index **1**, and compare that address to the **second** account your wallet shows you. That's where the paths actually differ, so it's the only reliable check. If none of the paths match your wallet's second account, your wallet may use a derivation scheme this tool doesn't support — in that case, don't run a search, since you won't be able to use the results.

---

## How matching works

If you give both a prefix and a suffix, the tool looks for either one — an address matching just one of them still counts, and that finds a match about twice as fast as requiring both.

**About case sensitivity:** for Ethereum-style addresses, it's best left off. The mixed upper/lowercase letters you sometimes see in an address are just a built-in typo-check, not part of the address itself — turning case sensitivity on makes the search twice as slow for no real benefit. For Solana, case actually matters, since Solana addresses use a different kind of encoding.

When case sensitivity is turned on, a prefix like `dead` will only match an address that's either entirely lowercase (`dead…`) or entirely uppercase (`DEAD…`) at that spot — never a mix of both. It doesn't matter which case you type it in yourself; typing `dead`, `DEAD`, or `Dead` all search for the same two possibilities.

Patterns that could never be found are rejected up front, before any searching starts — for example, letters that don't appear in the relevant address format at all.

---

## Difficulty and timing

Roughly how many addresses need to be checked, on average, to find one match:

| Pattern length | Ethereum-style (case doesn't matter) | Solana |
|--:|--:|--:|
| 3 characters | 4,096 | 195,112 |
| 4 characters | 65,536 | 11,316,496 |
| 5 characters | 1,048,576 | 656,356,768 |
| 6 characters | 16,777,216 | 38,068,692,544 |

Solana addresses use a much larger set of possible characters per position, which is why longer Solana patterns get expensive so much faster than Ethereum ones.

On a typical 8-core machine:

| Pattern | Roughly how long |
|:--|--:|
| 6 characters, Ethereum-style | ~2 minutes |
| 7 characters, Ethereum-style | ~35 minutes |
| 8 characters, Ethereum-style | ~9 hours |
| 4 characters, Solana | under a minute |
| 5 characters, Solana | ~50 minutes |

These are just averages — a real search is random, so it might finish instantly or take a few times longer than expected. The tool shows you its own estimate before it starts searching.

---

## Stopping and resuming

You can press `Ctrl-C` at any time to stop. The tool shuts down cleanly and tells you where to pick back up:

```
Summary
  Checked   : 164,608 addresses in 00:00:02 (57,882/s)
  Matches   : 0
  Resume from index : 161,789
```

Next time, just enter that number as your start index. It's set slightly earlier than where it actually stopped, just to make sure nothing gets skipped. If a search finishes its whole range with nothing left to check, this line won't appear at all.

If your computer crashes or the terminal window closes unexpectedly, the search shuts itself down safely within about a second rather than continuing to run in the background.

---

## Seed phrase validation

Before doing anything else, your seed phrase is checked against the official list of valid words. There's no way to bypass this — a phrase using made-up or incorrect words can't unlock any real wallet, so any address found from it would be useless.

1. It must be 12, 15, 18, 21, or 24 words long.
2. Every single word must be a real, recognized word. If any aren't, you'll be told exactly which ones and given suggestions:

```
These words are not in the official BIP39 English wordlist (2048 words):
  word 12: 'abuot'   did you mean: about, boat, auto?
```

3. The words together must pass a final built-in checksum. If every word looks correct individually but this still fails, one is likely out of order.

Extra spaces or capital letters in what you type don't matter — the tool cleans that up automatically before checking.

---

## Verification

The math behind this tool is checked against official, published test cases — not just tested against its own output:

- Verified against the official test phrases used to check seed-phrase tools generally, across every supported phrase length
- Verified against known, published test keys for both the Ethereum-style and Solana-style derivation methods
- Verified against real seed-phrase-to-address examples from MetaMask and Ledger
- Verified that splitting the search across multiple CPU cores never skips or double-checks any address
- Verified that stopping the tool in any way — Ctrl-C, a crash, closing the terminal — always shuts down cleanly

You can also spot-check it yourself. There's a famous, publicly known test seed phrase (all the word "abandon" repeated, ending in "about") that's used across the industry and holds no real funds. On the standard path, it should always produce:

| Index | Address |
|--:|:--|
| 0 | `0x9858Ef…34EcaEda94` |
| 1 | `0x6Fac4D…4E424Ab9C0` |
| 2 | `0xb67169…8e6802D7A` |

Every correctly working wallet agrees on these addresses, so if you see the same thing here, that's a strong sign everything's working correctly.

---

## FAQ

<details>
<summary><strong>Does this create a new wallet or a new key?</strong></summary>

No. Every address it finds already exists inside your seed phrase and always has — the tool just tells you where to look. Your backup and recovery phrase don't change at all.
</details>

<details>
<summary><strong>Do I have to handle the private key myself?</strong></summary>

Only for accounts further down the list. Nearby ones, your wallet can add with a couple of clicks. For a distant one, like index 120,627, you export that specific private key from this tool and import it into your wallet as a separate account.

The search itself never shows private keys — they only appear when you deliberately choose *Private key lookup*.
</details>

<details>
<summary><strong>Is a high index like 120627 safe to use?</strong></summary>

Yes — it's exactly as secure as index 0, just a different number in the same process.

The only real difference is how you get to it: your wallet can't jump straight there on its own, so you import it manually using its private key. After that, it behaves like any other account in your wallet, though your wallet won't rediscover it automatically if you ever restore from scratch — so keep a note of the path and index.
</details>

<details>
<summary><strong>Why is Solana so much slower to match?</strong></summary>

Solana addresses are built from a much larger set of possible characters per position than Ethereum-style addresses, so each extra character you ask for multiplies the difficulty by a lot more.
</details>

<details>
<summary><strong>The address it found isn't showing up in my wallet.</strong></summary>

This almost always means you picked the wrong derivation path. Look up index **1** and compare it to the second account your wallet shows you — index 0 looks the same across every path, so it won't tell you anything. See [Derivation paths](#derivation-paths) above.
</details>

<details>
<summary><strong>Does a passphrase (sometimes called a "25th word") work?</strong></summary>

Yes. Using a passphrase generates a completely different set of addresses, and this tool supports that — but the results will only match your wallet if the same passphrase is also set up there.
</details>

---

## Implementation notes

Each file is fully self-contained — no shared code between them, and nothing needed beyond a few common cryptography packages. The search is split evenly across all your CPU cores, with each core checking a different, non-overlapping slice of the index range, so every address is checked exactly once with nothing missed or repeated.

Numbers you type in (like index ranges) are always read precisely, so something like `1.005m` is interpreted as exactly 1,005,000, with no rounding errors.

