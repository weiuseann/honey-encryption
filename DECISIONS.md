# Decisions

This file is the single source of truth for the project's scope and the reasoning behind design
choices. It overrides the original plan PDF wherever they differ. Add a log entry whenever you make a
non-obvious call, and use this file to drill each other for Q&A.

## Agreed project summary (verbatim)

Format: one big project, honey encryption (HE), build it then break it.
Title: "Honey Encryption: Implementation and Cryptanalysis Under
Distribution Mismatch and Public Verification"

Framework
- PIN -> key via SHA-256 + salt (deliberately weak; we discuss why even
  Argon2 wouldn't save a 10,000-PIN space)
- AES-CTR with a random nonce per ciphertext, stored with it
- No authentication/padding check, since that would reveal the correct PIN
  (we show GCM/CBC padding failing as a side demo)

Scenario A: credit cards
- Weak DTE (random 16 digits) vs good DTE (inverse-CDF over network,
  real BINs, random digits, Luhn)
- Good DTE validated with round-trip tests and distribution checks
  (chi-square)
- Attacks evaluated separately: format filtering, PIN popularity
  (DataGenetics frequencies, cited), bank side info, last-4 digits,
  two cards under one PIN
- Two-card attack only works if the real cards are correlated (e.g. same
  bank) while the DTE samples each card independently. Real card pairs
  must be generated from a correlated model.

Scenario B: RSA private keys
- Real-size keys with a next-prime DTE (encode range matched to the
  nextPrime convention of the library we use)
- Real primes generated from the same range the DTE covers, so every
  prime is representable
- Tests: round trip, decoys are valid primes of the intended size,
  boundary/prime-gap cases
- Bias of the DTE acknowledged openly, not claimed to match real RSA
  key distribution
- Broken by checking N mod p against the public key
- Framed as "HE can't hide a secret that's verifiable from public info",
  not a break of RSA or AES

Core claim
- 1 in 10,000 attacker success is the baseline only under uniform PINs,
  a correctly matched DTE, and no side info
- We measure how far attacker success rises above that baseline under
  realistic assumptions

## Status

| Part | Status |
|---|---|
| Framework (`framework/he.py`), DTE base, weak card DTE, brute force, tests | Done |
| Good card DTE, RSA prime DTE | Stub |
| Attacks: format filter, PIN ranking, side info, two-card, RSA verify | Stub |
| Experiments: card pairs, success vs baseline, AES mode pitfall | Stub |
| `data/bin_list.csv`, `data/pin_frequencies.csv` | Header only |

## Decision log

Newest entries go at the bottom. Format: **decision**, why, then where it lives in the code.

### 2026-10-16: AES-CTR only, no GCM or CBC
**Why:** CTR has no tag and no padding, so decrypting under every PIN "succeeds" and gives a random
seed, which the DTE turns into a decoy. A GCM tag check or a CBC padding check would act as a
"wrong PIN" oracle and defeat HE before the DTE matters.
**Where:** `framework/he.py`; side demo in `experiments/aes_mode_pitfall.py`.

### 2026-10-16: Key = SHA-256(salt || PIN), deliberately fast
**Why:** a slow key-derivation function only multiplies the cost of each guess by a constant, and
10^4 guesses times even 1 s is under 3 hours. With a 10,000-PIN space the protection has to come from
the decoys. Keeping it fast also makes 1,000-trial experiments practical.
**Where:** `framework/he.derive_key`.

### 2026-10-16: Random salt and nonce per ciphertext, stored in the header
**Why:** the salt stops one precomputed PIN→key table from working on every ciphertext. A fresh nonce
avoids CTR keystream reuse, which would leak the XOR of two seeds. Both are public by design.
The layout is `salt (16 B) || nonce (16 B) || body`.
**Where:** `framework/he.Ciphertext`.

### 2026-10-16: API is `encrypt(dte, message, pin)`, not `encrypt(message, pin)`
**Why:** the framework needs to know which DTE to use. Passing the DTE explicitly keeps the framework
the same for cards and RSA.

### 2026-10-16: The DTE contract has three rules: round trip, decode never raises, uniformity
**Why:** a wrong PIN produces random seed bytes. If `decode` raised or returned something obviously
invalid, the attacker would learn "wrong PIN" for free.
**Where:** `dte/base.py`; each DTE's tests should check the first two rules.

### 2026-10-16: Weak card DTE uses a 128-bit seed, `encode = r·10^16 + m`, `decode = seed mod 10^16`
**Why:** the naive encoding (`m.to_bytes(8)`) leaks. The real seed is always < 10^16, but a random
8-byte seed is < 10^16 only about 1 time in 1,844, so the attacker could pick the real card by checking
the seed range. With a random `r` in a 128-bit seed, the bias is at most 10^16/2^128 ≈ 3·10^-23. The
weak DTE is then weak only in its message distribution (uniform 16 digits fail Luhn/BIN checks), which
is the weakness we want to demonstrate.
**Where:** `dte/weak_card.py`.

### 2026-10-16: Seed length varies per DTE
**Why:** RSA primes need much longer seeds than cards. CTR needs no block alignment, so the framework
accepts any `seed_length`.

### 2026-10-16: Optional `rng` on `encrypt` and `DTE.encode`
**Why:** experiments must be reproducible. Passing `random.Random(seed)` fixes the salt, nonce and
encoding randomness. The default is `secrets.SystemRandom()` (the OS CSPRNG), and real usage must use
it. Only the `random.Random` interface is supported, because numpy's `integers()` can't draw 128-bit or
RSA-size ranges.
**Where:** `dte/base.default_rng`, `framework/he.encrypt`.

### 2026-10-16: `data/` holds the BIN table and the DataGenetics PIN frequencies
**Why:** keeps data separate from code, and the sources are cited in one place.
**Where:** `data/README.md` (formats and sources).

## Open decisions

- Good card DTE: seed length, and how to handle rounding in the inverse-CDF intervals.
- Good card DTE: the source of the BIN list and the weights.
- RSA DTE: prime size, the exact prime range and its boundary handling with `sympy.nextprime`
  (which returns the smallest prime strictly greater than its input).
- PIN frequencies: how to spread probability over PINs not listed in the DataGenetics data.
- Correlated card-pair model: what `rho` means and which values to sweep.
- Who owns which half (proposed: cards = Person A; framework, RSA and AES demo = Person B).
- Presentation date and timeline.
