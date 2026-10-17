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
| Good card DTE (`dte/good_card.py`), Luhn helper (`dte/luhn.py`), their tests | Done |
| RSA prime DTE | Stub |
| Attacks: format filter, PIN ranking, side info (bank, last-4), shared ranking helper, their tests, demo | Done |
| Attacks: two-card, RSA verify | Stub |
| Experiments: card pairs, success vs baseline, AES mode pitfall | Stub |
| `data/bin_list.csv` | Done (20 BINs) |
| `data/pin_frequencies.csv` (+ uniform-tail variant, generator) | Done |

## Ownership

| Part | Owner |
|---|---|
| Good card DTE, chi-square test, BIN and PIN data | Seann |
| Format filter, PIN ranking, side info (bank, last-4) attacks | Seann |
| RSA prime DTE, RSA verify attack | Kee |
| AES mode pitfall demo | Kee |
| Card pair generator, two-card attack | Kee (needs the good card DTE first) |
| Success vs baseline experiment, plots, slides | Both |

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

### 2026-10-17: Good card DTE scope is 16-digit Visa and Mastercard, 6-digit BINs
**Why:** the message format is 16 digits, so Amex (15) and other lengths are out. Structure is
network → 6-digit BIN → 9 uniform middle digits → computed Luhn digit. Real issuers moved to 8-digit
BINs in 2022 and allocate middle digits unevenly; we don't model either, and say so as a known
mismatch an attacker could exploit.
**Where:** `dte/good_card.py`.

### 2026-10-17: Good card DTE uses a 128-bit seed and integer-weight intervals, no floats
**Why:** float inverse-CDF intervals round at the boundaries, which can break exact reversibility or
skew probabilities. Instead each BIN has an integer weight `w_i` and owns exactly `w_i` of
`W = Σw_i` slots (rows sorted by network, so each network is one contiguous block). A card is the
integer `u = slot·10^9 + middle < M = W·10^9`, and `encode = r·M + u` with a random slot in the
BIN's block and random `r < 2^128 // M`; `decode = int(seed) mod M`. This is the weak DTE's trick in
mixed radix: exact round trip, `P(BIN i) = w_i/W` exactly, and bias at most `M/2^128 ≈ 3·10^-27`
for `W = 1000`. The constructor refuses tables where the bias bound would exceed `2^-64`. 16 bytes
also matches the weak DTE, so ciphertext length doesn't reveal which DTE is in use.
**Where:** `dte/good_card.py` (docstring has the full argument); boundary tests in
`tests/test_good_card_dte.py`.

### 2026-10-17: BIN table from a public aggregator, weights are our assumption
**Why:** no issuer publishes BIN lists or per-BIN card counts. 18 of the 22 BINs come from a
third-party BIN database (Singapore issuers: DBS/POSB, OCBC, UOB, Citibank, Standard Chartered,
Maybank) and are marked `aggregator`. 4 are made up to fill gaps and are marked `illustrative`.
Weights are hand-set integers: Visa 600 / Mastercard 400, larger banks weighted higher. The
chi-square test only checks the DTE against these weights, not against reality.
**Where:** `data/bin_list.csv`, sources and caveats in `data/README.md`.

### 2026-10-17: Luhn lives in a shared module
**Why:** the good DTE, the format filter and the card pair generator all need it, so there is one
implementation to test and explain.
**Where:** `dte/luhn.py`, `tests/test_luhn.py`.

### 2026-10-17: Experiments generate "real" cards by sampling the good DTE
**Why:** the 1/10,000 baseline assumes the real message is drawn from the same distribution the DTE
decodes to. Generating real cards with `GoodCardDTE.sample(rng)` (decode a random seed) makes that
hold exactly, so any rise above the baseline comes from the attack being measured (PIN popularity,
side info, correlated pairs), not from an accidental mismatch between our test data and the DTE.
Any real card must also use a BIN from the table, or `encode` raises. The correlated card-pair
generator should draw its BINs from this table for the same reason.
**Where:** `GoodCardDTE.sample` in `dte/good_card.py`; to be used by `experiments/card_pairs.py`
and `experiments/success_vs_baseline.py`.

### 2026-10-17: Removed the two illustrative UOB Visa BINs; Visa rebalanced to keep 60/40
**Why:** the table already has real (aggregator-listed) UOB Mastercard BINs, so made-up UOB Visa
rows only added unverifiable data. Their 100 weight went back to other Visa BINs (DBS +40, OCBC +30,
Citibank +15, Maybank +15), keeping the assumed 60/40 network split. The table is now 20 BINs:
18 aggregator, 2 illustrative.
**Where:** `data/bin_list.csv`, `data/README.md`.

### 2026-10-17: Every attack returns a full guess order; ties are broken at random
**Why:** a ranked list lets the harness record the true PIN's rank and lets attacks be combined
(e.g. filter, then PIN popularity, as a tuple score). Ties must be broken randomly with the
experiment's seeded rng: against the good DTE all 10,000 candidates tie under the format filter,
and breaking ties by PIN order would always guess 0000 first, inflating success above 1/10,000
whenever victim PINs are non-uniform.
**Where:** `attacks/ranking.py` (`order_by_score`, `rank_of`), used by both attacks.

### 2026-10-17: Format filter has three cumulative stages and uses the DTE's own BIN table
**Why:** Luhn, then network prefix, then BIN-in-table, each using only public knowledge. Giving the
attacker the same BIN table as the good DTE is the matched-DTE setting: the filter then removes no
good-DTE decoy, while for the weak DTE it leaves about 0.02 expected decoys (10,000 → ~1,000 →
~155 → real card).
**Where:** `attacks/format_filter.py`.

### 2026-10-17: PIN distribution = published DataGenetics values + a calibrated two-tier model
**Why:** DataGenetics publishes only the top 20, the bottom 21 and some cumulative points. We keep
those 41 values exactly. The other PINs are split into a "pattern" tier (MMDD dates, years
1900-2029, ABAB pairs: 564 PINs) at `k·b` and a "base" tier at `b`, with `b` and `k` solved from two
published facts (total = 1, top 426 = 50%). Which PINs are patterns is our assumption. A
uniform-remainder variant is kept as a sensitivity check.
**The model understates PIN concentration**: against published figures it gives the top 61 PINs
29% (published ~33%) and the bottom 4,200 PINs 18% (published < 10.7%). Real PINs are more
predictable than our table, so **all attack success we report is a conservative lower bound**.
**Where:** `data/build_pin_frequencies.py` → `data/pin_frequencies.csv`,
`data/pin_frequencies_uniform_tail.csv`; published vs assumed numbers in `data/README.md`.

### 2026-10-17: The attacker is assumed to know the PIN distribution exactly
**Why:** experiments draw victim PINs from the same table the attacker ranks by. This is the
strongest-attacker assumption and the standard one for HE's bound (rank-1 success ≈ probability of
the most popular PIN, 10.7%). A mismatched prior (attacker's table differs from victims') would only
lower the attacker's success, and could be a later sensitivity run.
**Where:** `attacks/pin_ranking.py` (`rank_by_pin_popularity`, `sample_pins`).

### 2026-10-17: Side info = known bank and known last 4, combined through one consistency flag
**Why:** the attacker ranks first the candidates consistent with every known fact, then breaks ties
by PIN popularity (if used), then randomly. A candidate matching only some facts is certainly a
decoy, so ordering partial matches can't change the real card's rank; one flag is simpler than a
per-fact tuple. Expected rank-1 success against the good DTE (demo, 200 trials, seed 2026):
bank only ≈ (number of banks)/10,000 ≈ 0.07% (measured 0.000, median rank ~670); last-4 only
≈ 1 − 1/e ≈ 63% (measured 70.5%), since about one decoy in 10^4 shares the last 4; bank + last-4
≈ 90% (91.5%); bank + last-4 + PIN ≈ 95% (95.5%). The last 4 include the Luhn check digit, but it
depends on uniform digits, so the match rate is still about 1/10^4.
**Where:** `attacks/side_info.py`, rows in `experiments/demo_card_attacks.py`.

### 2026-10-17: Side information is assumed accurate
**Why:** we model an attacker who really knows the victim's bank and last 4 (from a receipt, a
banking app or a statement). If the fact were wrong, the real card would rank last. Noisy side info
is not modelled.
**Where:** `attacks/side_info.py` (module docstring).

### 2026-10-17: DBS and POSB are separate banks for the bank attack
**Why:** we match the `bank` column of `data/bin_list.csv` exactly. POSB is DBS's consumer brand, so
an attacker who only knows "DBS group" would have a weaker filter; treating them separately assumes
the attacker knows which brand is on the card, which is what a receipt or card face shows.
**Where:** `attacks/side_info.matches_bank`.

### 2026-10-17: Card product filter dropped (future work)
**Why:** the stub's `filter_by_product` was out of scope. Our table's `product` is only credit/debit,
which removes about half the decoys at most. A real product dataset (card tiers per BIN) would make
it worth adding.
**Where:** not implemented.

### 2026-10-17: Discussion note: first 6 + last 4 is a stronger leak than bank + last 4
**Why:** PCI DSS allows merchants to display the first 6 and last 4 digits of a card together
(e.g. on receipts). The first 6 is the BIN itself, a much finer filter than the bank: against our
table it would leave about 10,000 × w_BIN/1000 × 10^-4 decoys, essentially none. We don't implement
it, but it should be mentioned in the slides as a limitation of HE for card numbers: the DTE can
only hide what the attacker can't already see.
**Where:** discussion only.

## Open decisions

- RSA DTE: prime size, the exact prime range and its boundary handling with `sympy.nextprime`
  (which returns the smallest prime strictly greater than its input).
- Correlated card-pair model: what `rho` means and which values to sweep.
- Presentation date and timeline.
