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
| RSA prime DTE | Done: domain, decoder, sampler, encoder, real-prime generation, framework integration, exact toy bias counts, and 1024-bit smoke checks |
| Attacks: format filter, PIN ranking, side info (bank, last-4), shared ranking helper, their tests, demo | Done |
| Attacks: two-card (k cards, simple + Bayes-optimal rule), its tests, demo rows | Done |
| Attacks: RSA verify | Done: proper-divisor filter plus small and real-size end-to-end evidence |
| RSA narrated demo (`experiments/demo_rsa.py`) | Done: small demonstration and full 10,000-PIN 1024-bit run verified and recorded |
| Experiments: card pairs (`generate_wallet`), demo (`demo_card_attacks.py`), Bayes prediction check (`check_bayes_prediction.py`) | Done |
| **Next (Kee):** final harness `experiments/success_vs_baseline.py` | Stub. Card setups to cover, each vs the 1/10,000 baseline and the 10.7% top-PIN bound: weak and good DTE under format filter, PIN ranking and format + PIN; good DTE with side info (bank, last-4, bank + last-4, bank + last-4 + PIN); two-card k = 2/3/5 with the simple rule and the Bayes rule (Bayes for any rho sweep); and the PIN-ranking setups re-run with `pin_frequencies_uniform_tail.csv` as the sensitivity check |
| Experiments: AES mode pitfall | Done: seeded three-mode acceptance comparison, measured counts, CLI, and tests |
| `data/bin_list.csv` | Done (20 BINs) |
| `data/pin_frequencies.csv` (+ uniform-tail variant, generator) | Done |

## Ownership

| Part | Owner |
|---|---|
| Shared base (framework, weak DTE, brute force) | Seann |
| Good card DTE, Luhn helpers, BIN and PIN data | Seann |
| Format filter, PIN ranking, side info attacks | Seann |
| Card pair generator, two-card attack | Seann |
| RSA prime DTE, RSA verify attack | Kee |
| AES mode pitfall demo | Kee |
| Final experiment harness (experiments/success_vs_baseline.py), results and charts | Kee |
| Slides, demo script, Q&A prep | Both |

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

### 2026-10-17: Ownership change: card pairs and two-card attack moved to Seann
**Why:** Kee handed over `experiments/card_pairs.py` and `attacks/two_card.py`; Kee owns the slides
and charts instead.
**Where:** Ownership table above.

### 2026-10-17: rho = probability that all k cards in a wallet share one bank
**Why:** simplest model that generalises from pairs to k cards. With probability rho, one bank is
drawn by its share and all k cards are drawn from the good DTE conditioned on it (rejection
sampling); otherwise the k cards are independent DTE draws, which still share a bank by chance with
probability `S_k = Σ q_b^k`. Each card alone keeps exactly the DTE's distribution, so the attack can
only exploit correlation between cards. This is not a per-card correlation model.
**Where:** `experiments/card_pairs.generate_wallet`.

### 2026-10-17: Two-card attack generalised to k cards; simple rule by default, Bayes-optimal with rho
**Why:** each card is encrypted under the same PIN with its own salt and nonce; brute force groups
the k decryptions by PIN. The simple rule ranks wallets whose cards all share a bank first, then by
PIN popularity, ties random. It is easy to explain but at rho < 1 it can do worse than PIN-only
(mixed real wallets are pushed behind same-bank decoys). The optional Bayes-optimal score
`P(PIN) · (rho · q_b^(1-k) + (1 - rho))` for same-bank wallets, `P(PIN) · (1 - rho)` otherwise,
reduces to PIN ranking at rho = 0, so the attacker never does worse than PIN-only. **Any rho sweep
must use the Bayes rule.** At rho = 1 it does **not** reduce to the simple rule: mixed wallets are
dropped as in the simple rule, but same-bank wallets are scored `P(PIN) · q_b^(1-k)`, so a match on a
rare bank counts for more than a match on DBS.
Results against the good DTE, rho = 1. Predicted values use the model's numbers (Poisson
approximation over the 9,999 decoy wallets, `experiments/check_bayes_prediction.py`); measured values from
the demo (200 trials, seed 2026) and a separate 1,000-trial run of k = 5 through the full pipeline
(seed 7000, reproducible with `python -m experiments.check_bayes_prediction`):

| k | same bank only | same bank + PIN: predicted / measured | Bayes (rho = 1): predicted / measured |
|---|---|---|---|
| 2 | 0.05% / 0.0% | 18.8% / 19.5% | 19.3% / 20.5% |
| 3 | 0.2% / 0.0% | 23.8% / 24.5% | 27.9% / 30.0% |
| 5 | 2% / 2.0% | 37.2% / 34.0%; 36.5% ± 3.0% (1,000 trials) | 60.6% / 67.0%; **59.8% ± 3.0% (1,000 trials)** |

The demo's 67% at k = 5 was about two standard errors of noise; the 1,000-trial value matches the
prediction. The 1,000-trial run also re-checked every Bayes ranking against an independently
computed score (no mismatches).
**Why Bayes is so much stronger at k = 5:** five random cards all landing on DBS happens about 1 time
in 260 (`0.33^5`); all on UOB about 1 in 170,000. So about 39 of the ~45 surviving decoy wallets are
DBS (DBS is 87% of `S_5`), and almost none are from small banks. The simple rule ignores this and
makes the real wallet compete with all ~45 survivors on PIN popularity alone, so a victim with an
ordinary PIN (41% of victims) almost always loses. The Bayes rule weights each same-bank wallet by
`1/q_b^4` (84 for DBS, 15,242 for UOB, 243,865 for Maybank), so a small-bank wallet beats the DBS
decoys even with an ordinary PIN. Predicted / measured P(win | victim's bank): DBS 30% / 28%,
OCBC 47% / 50%, POSB 77% / 75%, Standard Chartered 91% / 90%, UOB 95% / 97%, Citibank 97% / 95%,
Maybank 99.8% / 100%. A DBS victim gains almost nothing, because their wallet looks like the
commonest kind of decoy.
**Where:** `attacks/two_card.py`, rows in `experiments/demo_card_attacks.py` (`--trials`, default
200; about 3 minutes).

### 2026-10-17: Absolute two-card numbers depend on our assumed bank shares
**Why:** the attack's strength is set by `S_k = Σ q_b^k` and, for the Bayes rule, by how skewed the
shares are. The bank shares come from our hand-set BIN weights (`data/README.md`), not measured
data, so the absolute success rates are illustrative. The qualitative result holds for any shares:
more cards under one PIN → fewer surviving decoys → success rises toward the PIN-popularity limit
and beyond.
**Where:** discussion; `data/bin_list.csv` weights.

### 2026-10-17: Ownership table revised
**Why:** Seann owns everything on the card side (shared base, good DTE, data, all card attacks, card
pairs). Kee owns the RSA half, the AES pitfall demo and the final harness with results and charts.
Slides, the demo script and Q&A prep are shared. This replaces the earlier split where Kee owned
slides and charts and the harness was shared.
**Where:** Ownership and Status tables above.

### 2026-10-18: RSA DTE domain bounds and seed capacity (Kee, task 2.1)
**Decision:** support Python integer bit counts `b >= 3`, rejecting booleans and non-integers.
Let `L = 2**(b-1)`, `U = 2**b - 1`, and `Pmax = prevprime(U + 1)`. Prepare the
next-prime input domain `x = L-1` through `Pmax-1`, inclusive, with
`M = Pmax - (L-1)` possible values. This covers every b-bit prime. For b=4,
the input domain is 7 through 12; nextprime outputs only 11 or 13.
**Why:** `nextprime` is strictly greater than its input. Allowing x up to U can
produce a (b+1)-bit prime; stopping before Pmax prevents that overflow while
retaining the largest valid prime. Starting at L-1 retains the smallest valid
prime. Using `prevprime(U+1)` includes U when U itself is prime (e.g. b=3, U=7).
**Seed capacity:** use `ceil((b+128)/8)` bytes, expressed with integer arithmetic
as `(b+128+7)//8`. At least 128 extra bits make future modulo-reduction bias
negligible; this does not fix the separate prime-gap bias. Final demonstrations
are planned with 1024-bit factors; the constructor remains configurable for tests.
**Where:** `dte/rsa_prime.py` constructor, `tests/test_rsa_prime_dte.py`.
Only configuration is implemented in this task; encoding, decoding, and real-prime
generation are still stubs. Their behavior is not claimed verified yet.

### 2026-10-18: RSA seed decoding is total for the configured length (Kee, task 2.2)
**Decision:** interpret seed bytes as a big-endian unsigned integer z, compute
`x = (L-1) + (z % M)`, and return `int(nextprime(x))` using task 2.1's bounds.
Reject a seed only if its length differs from the configured byte length; no
correctly sized byte string is rejected for its value or decoded candidate.
**Why:** wrong PINs yield arbitrary seed bytes. Rejecting any value within the
expected seed length would provide a wrong-PIN clue. The bounded x range keeps
all outputs within the configured prime bit length. Big-endian ordering matches
the existing card encoders. The decoder is deterministic and draws no randomness.
**Validation:** small domains are checked against independently enumerated primes
using trial division, including every residue at low and high seed values; tests
also cover zero/all-one seeds, seeded random bytes, and malformed lengths.
**Where:** `RSAPrimeDTE.decode` and `tests/test_rsa_prime_dte.py`. Encoding and
real-prime generation remain stubs; end-to-end RSA encryption is not complete.

### 2026-10-18: Random seed preimages use rejection sampling (Kee, task 2.3)
**Decision:** a private integer helper takes the target's inclusive residue interval,
modulus M, seed-space size S, and caller RNG. Draw residue j uniformly from the
interval and repetition r uniformly from 0 through `S//M`, form `z = r*M+j`,
and retry if `z >= S`. The helper returns the accepted integer; serialization
and choosing the interval for a prime belong to the future encoder.
**Why:** each proposed pair has equal probability and each valid seed has one
representation. Rejecting out-of-range pairs therefore samples exactly uniformly
from the valid preimages, including the partial last block. This is simpler than
weighted interval bookkeeping. The extra repetition when S is divisible by M is
always rejected; with the actual slack-bit seed space, retries are negligible.
**Validation:** enumerate toy proposal pairs and compare accepted seeds against
independently enumerated remainder membership. Force rejection followed by success,
cover a singleton interval and a divisible seed space, and check reproducibility
and decoder compatibility at actual seed capacity. For S=16, M=6, residues 4..5,
the valid seeds are exactly 4, 5, 10, and 11.
**Where:** `_sample_seed_integer` in `dte/rsa_prime.py` and its tests. The helper
requires valid internal bounds and explicit randomness; future `encode` will
validate messages and supply the caller RNG or secure default. Encoding and
real-prime generation are not implemented by this task.

### 2026-10-18: RSA encoding inverts strict next-prime intervals (Kee, task 2.4)
**Decision:** accept integer primes in the configured domain, rejecting booleans,
non-integers, composites, and out-of-range values. For prime p, its valid
next-prime inputs run from `max(L-1, prevprime(p))` through `p-1`, inclusive.
Subtract L-1 to obtain residue bounds, call the existing uniform preimage
sampler, then serialize its integer as exactly the configured big-endian bytes.
Use the supplied RNG or `default_rng()` when absent; no fixed seed in library code.
**Why:** `nextprime(p)` skips p, so including p in the encoding interval breaks
round trips. Clipping the first interval to L-1 makes it match the decoder's
actual domain. Sampling a full seed preimage rather than storing p directly
allows randomized encodings of the same prime and avoids exposing a small-seed
representation. This does not remove the documented prime-gap distribution bias.
**Where:** `RSAPrimeDTE.encode` and its tests. Tests cover all primes in small
domains, seeded 16-bit samples, explicit first/last gap endpoints, controlled
distinct seeds, repeatability, RNG selection, fixed-length bytes, and invalid inputs.
Real-prime generation and the broader framework/bias checks remain future tasks.

### 2026-10-18: Real RSA primes use independent odd-candidate rejection (Kee, task 2.5)
**Decision:** construct the existing RSA DTE domain, then draw odd integers uniformly
from `L+1` through Pmax inclusive using `randrange(L+1, Pmax+1, 2)`. Return the first
candidate accepted by `isprime`; retry composites. Use the supplied RNG or the
shared secure default. Constructor reuse keeps size validation and bounds in one place.
**Why:** all supported primes are odd for b>=3. Every supported prime appears once
in the uniform candidate set, so rejection gives uniform prime selection under
ideal uniform randomness. Generating victims through next-prime decoding instead
would favour larger preceding gaps and mask the DTE's distribution mismatch.
This is a teaching prime sampler, not a complete production RSA key generator;
SymPy's large-number predicate uses probable-prime testing rather than certificates.
**Where:** `generate_real_prime` and tests in `tests/test_rsa_prime_dte.py`.
Controlled RNGs exercise composite rejection and both boundary primes, including
the prime upper endpoint. Tests also cover bit length, independent small-prime
checks, encodability, reproducibility, secure-default selection, and invalid sizes.
Full framework integration, real-size smoke checks, and explicit bias counts
remain task 2.6; no modulus/key-pair generation is added here.

### 2026-10-18: RSA DTE integration and bias evidence (Kee, task 2.6)
**Validation:** the unchanged AES-CTR framework recovers generated primes under
the correct PIN, and wrong PINs still decode to primes of the configured size.
Ciphertext serialization and seeded encryption repeatability are covered. Tiny
domains may collide, so tests do not assert every wrong-PIN output differs.
**Bias evidence:** tests temporarily shrink only their local DTE instance to
one-byte seeds and enumerate all 256 values. Expected counts use independently
enumerated primes, clipped preceding-gap widths, full modulo blocks, and the
partial final block. In the four-bit domain, 11 receives 172 seeds and 13 receives
84; with normal slack bits the probabilities approach 4/6 and 2/6. This confirms
prime-gap bias and distinguishes it from finite modulo bias rather than claiming
uniform decoys or agreement with production RSA key generation.
**Real-size smoke:** a seeded 1024-bit prime passes three DTE round trips,
framework correct-PIN recovery, zero/all-one seed decoding, and one wrong-PIN
decryption. Seeds are 144 bytes; serialized ciphertexts are 176 bytes. SymPy
large-number primality checks are probable-prime checks, not certificates.
**Where:** `tests/test_rsa_prime_dte.py`, `dte/rsa_prime.py` explanation, and
README RSA usage/limitations. The DTE component is complete; RSA public
verification and the full 10,000-PIN experiment remain separate unfinished work.

### 2026-10-18: RSA verification returns all proper-divisor matches (Kee, task 3.1)
**Decision:** `find_real_prime` keeps every candidate pair satisfying
`1 < candidate < N` and `N % candidate == 0`, preserving input order and duplicate
matches. Reject boolean/non-integer N and values N<=3 before processing candidates.
N is assumed to be a supplied RSA modulus; these checks do not certify its key
structure or compositeness. Candidate integers come from the DTE, so this filter
does not repeat primality testing or factor N from scratch.
**Why:** zero is unsafe to divide by, and 1 or N are trivial divisors. Both RSA
factors may occur in candidates, and multiple PINs may produce the same factor,
especially in toy domains. Selecting the first match or asserting exactly one
would confuse factor recovery with unique original-PIN recovery.
**Example:** with N=143, candidates 11 and 13 divide N; 17 does not. Every
associated matching PIN is retained, including duplicate rows.
**Where:** `attacks/rsa_verify.py`, `tests/test_rsa_verify.py`. This demonstrates
public verification of guessed secrets, not a break of AES or an algorithm for
factoring an arbitrary RSA modulus without candidate factors. Full encryption,
10,000-PIN enumeration, and narrated reporting remain tasks 3.2 and 3.3.

### 2026-10-18: Narrated RSA trial and optional arithmetic acceleration (Kee, tasks 3.2-3.3)
**Decision:** `experiments/demo_rsa.py` composes existing prime generation,
encryption, all-PIN brute force, and public verification. It generates distinct
p/q with a recorded seeded RNG, chooses a uniform PIN, and reports all matches,
distinct factor count, true-PIN survival, actual modulus size, and separate
enumeration/verification timings. The default uses reduced 16-bit factors.
**Why:** factor recovery and original-PIN uniqueness are different outcomes.
The seed-2026 reduced-size example leaves 10 matching PINs across two factors;
the true PIN survives. Real-size enumeration must be explicitly requested.
**Reproducibility:** optional non-overwriting JSON output records generated inputs,
software/backend versions, Git revision/dirty flag, and relevant source hashes.
Repeated small trials reproduce deterministic fields; timings are measurements.
**Performance:** 10 1024-bit guesses took 3.653s with the pure-Python SymPy backend,
estimating roughly 61 minutes. The installed SymPy source confirms automatic
gmpy2 support; optional gmpy2 2.3.2 was installed in the local environment, without
making it a mandatory requirement. The same inputs then took 0.484s for 10 guesses,
estimating roughly 8 minutes. These are estimates; full measurements are recorded
separately once complete. No DTE/AES/attack algorithm was replaced or prime size
reduced for speed. Benchmark p/q/N/PIN/ciphertext match across both backends.
**Where:** `experiments/demo_rsa.py`, `tests/test_demo_rsa.py`, README usage;
benchmark artifacts in the external OpenSpec change directory. User explicitly
requested applying tasks 3.2 and 3.3 together for this turn.

### 2026-10-18: Full real-size RSA experiment result (Kee, task 3.3)
**Measured:** seed 2026, two distinct 1024-bit factors, actual N size 2048 bits,
176-byte ciphertext, and all 10,000 candidate PINs. Public verification retained
exactly one PIN-factor pair: PIN `2381`, the true PIN, with the original p.
Brute-force enumeration took 777.2450963 seconds; verification took 0.045071
seconds; total measured trial time was 777.6313182 seconds. The approximately
8-minute accelerated ten-guess estimate understated the actual roughly 13-minute
run, illustrating why sample timing is not a runtime guarantee.
**Validation:** inspect p/q size, distinctness and primality predicate, p*q=N,
every match's proper divisibility, true-PIN membership, counts, and source hashes;
decrypt the saved ciphertext under the saved true PIN to recover p. Inputs match
the earlier accelerated benchmark exactly. There is one matching factor/PIN in
this measured run; uniqueness is not asserted as a universal guarantee.
**Environment/artifact:** Python 3.11.4, SymPy 1.14.0, cryptography 50.0.2,
optional gmpy2 2.3.2 (`gmpy` backend). Full record:
`../openspec/changes/kee-rsa-and-experiments/rsa-1024-full-seed-2026.json`.
The record includes generated inputs, actual timings, Git dirty state and source
checksums, because the new demo code was not yet committed. No all-PIN real-size
run is included in normal pytest.

### 2026-10-18: CTR acceptance comparison reuses the shared cipher helper (Kee, task 4.1)
**Decision:** use seeded experiment inputs with one 16-byte seed plaintext, salt,
and true PIN shared by the future three-mode comparison. Prepare separate
16-byte CTR/CBC IVs and a 12-byte GCM nonce. The CTR branch reuses `derive_key`,
`ALL_PINS`, and the existing internal `_aes_ctr` helper, leaving the framework
unchanged. It decrypts under every PIN and counts every output as accepted;
there is no plaintext-equality, padding, authentication, or DTE-validity check.
**Why:** the demo measures what a cipher can reject, not whether the original
seed was recovered. A wrong CTR key still produces bytes. Reusing the existing
helper avoids a second CTR implementation or a cipher abstraction layer.
**Validation:** all 10,000 PINs are attempted and accepted, correct-key decryption
recovers the seed, and a fixed wrong-key example returns different bytes without
error. Fixture lengths, seeded repeatability, and unknown/unimplemented modes
are tested. GCM/CBC and the three-mode CLI remain later tasks.
**Where:** `experiments/aes_mode_pitfall.py`, `tests/test_aes_mode_pitfall.py`.
The user requested independent work while the full RSA experiment was running;
this permits task 4.1 before that experiment finishes, without starting 4.2.

### 2026-10-19: GCM tag verification rejects candidate keys (Kee, task 4.2)
**Decision:** encrypt the shared fixture with AESGCM, then attempt all 10,000
PIN-derived keys against the same ciphertext/tag and 12-byte nonce. Count
successful authentication only. Catch `InvalidTag` specifically; do not compare
the output to the known secret plaintext or swallow unrelated errors.
**Why:** the attacker can perform this public acceptance test without knowing
the plaintext. It reveals wrong PINs before the DTE could provide decoys.
**Measured:** seed 2026 accepts one guess. Correct-key authentication and
selected wrong-key failures are tested; the fixture's measured count is not a
universal claim that false acceptance is mathematically impossible.
**Where:** `experiments/aes_mode_pitfall.py`, `tests/test_aes_mode_pitfall.py`.

### 2026-10-19: CBC acceptance is valid padding, not plaintext equality (Kee, task 4.3)
**Decision:** PKCS#7-pad the shared 16-byte seed (adding a complete padding block),
encrypt using CBC with the fixture's 16-byte IV, and count guesses only when
unpadding succeeds. Catch `ValueError` only around PKCS#7 unpadding, leaving
cipher setup and decryption errors visible. Add `--seed` CLI for all three modes.
**Why:** random decrypted last blocks occasionally have valid padding. Under a
random-output approximation, acceptance probability is sum(256**(-k), k=1..16),
about 1/255: roughly 39 wrong guesses plus the correct guess, not a guaranteed
single-digit count. No equality check against the original plaintext is used.
**Measured:** seed 2026: CTR 10000, GCM 1, CBC 45 accepted guesses out of 10000
per mode. CBC therefore accepted 44 wrong guesses in this experiment. Tests
cover known valid/invalid padding, correct-key recovery, all-PIN enumeration,
repeatability, and the CLI without requiring a universal exact CBC count.
**Where:** AES comparison module/tests and README usage. The existing CTR-only
framework is unchanged. User explicitly requested tasks 4.2 and 4.3 together.

## Open decisions

- Correlated card-pair model: which `rho` values to sweep (suggested 0, 0.25, 0.5, 0.75, 1; use the
  Bayes-optimal rule).
- Presentation date and timeline.
