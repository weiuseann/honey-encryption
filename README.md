# Honey Encryption: Implementation and Cryptanalysis Under Distribution Mismatch and Public Verification

We build honey encryption (HE), then measure how far an attacker's success rises above the
1/10,000 baseline. That baseline only holds with uniform PINs, a correctly matched DTE and no side
information. We never attack AES. Every attack targets the 4-digit PIN space and the DTE.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -v
```

Python 3.11+. Run everything from the repo root (`pytest.ini` puts the root on the import path).

## How it fits together

```
encrypt:  message --dte.encode--> seed --AES-CTR(SHA-256(salt||PIN), nonce)--> body
decrypt:  body ----AES-CTR-------> seed --dte.decode--> message   (never fails)
```

A wrong PIN decrypts to a random seed, and the DTE turns that seed into a decoy.

- **Why CTR:** CTR has no padding and no tag, so every PIN "succeeds". GCM or CBC with padding would
  tell the attacker which PINs are wrong (see `experiments/aes_mode_pitfall.py`).
- **Ciphertext layout:** `salt (16 B) || nonce (16 B) || body (seed_length B)`. Salt and nonce are
  public and fresh for every ciphertext.
- **The KDF is weak on purpose:** a slow KDF only multiplies the cost of each of the 10^4 guesses by a
  constant (see the comment in `derive_key`).

## Folder layout

| path | status | what it is |
|---|---|---|
| `framework/he.py` | done | `derive_key`, `encrypt`, `decrypt`, `Ciphertext`, `ALL_PINS` |
| `dte/base.py` | done | abstract `DTE` + `default_rng()` |
| `dte/weak_card.py` | done | uniform 16 digits (Scenario A baseline) |
| `dte/good_card.py` | done | inverse-CDF: network → BIN → digits → Luhn |
| `dte/luhn.py` | done | `luhn_check_digit`, `is_luhn_valid` (shared) |
| `dte/rsa_prime.py` | done | reversible next-prime DTE, separate prime sampler; gap-biased decoys |
| `attacks/brute_force.py` | done | decrypt under all 10,000 PINs |
| `attacks/format_filter.py` | done | Luhn / prefix / BIN filters |
| `attacks/pin_ranking.py` | done | DataGenetics PIN popularity |
| `attacks/ranking.py` | done | `order_by_score` (random tie-break), `rank_of` (shared) |
| `attacks/side_info.py` | done | known bank, known last 4 digits (combine with PIN ranking) |
| `attacks/two_card.py` | done | k cards under one PIN (simple and Bayes-optimal ranking) |
| `attacks/rsa_verify.py` | done | proper-divisor verification; preserves all matching PIN-factor pairs |
| `experiments/card_pairs.py` | done | correlated real-card wallet generator (`rho`) |
| `experiments/success_vs_baseline.py` | in progress | setup validation and raw matched-DTE baseline trials; other setups/statistics pending |
| `experiments/aes_mode_pitfall.py` | done | seeded CTR/GCM/CBC acceptance comparison and CLI |
| `experiments/demo_card_attacks.py` | done | real card's rank under every card attack (`--trials N`) |
| `experiments/check_bayes_prediction.py` | done | two-card attack: predicted vs measured rank-1 success (`--k`, `--trials`) |
| `data/` | done | `bin_list.csv`, `pin_frequencies.csv` (+ generator script); see `data/README.md` |
| `tests/` | done for the finished parts | pytest |

Each stub's docstring describes what goes there and the agreed requirements for it.

## The DTE interface

Every DTE subclasses `dte.base.DTE`:

```python
class DTE(ABC):
    seed_length: int                                   # bytes, fixed per DTE
    def encode(self, message, rng=None) -> bytes: ...  # message -> random matching seed
    def decode(self, seed: bytes): ...                 # ANY seed -> message
```

The contract, which each DTE's tests should check:

1. **Correctness:** `decode(encode(m)) == m`.
2. **Totality:** `decode` never raises on random bytes of length `seed_length`. Wrong PINs produce
   random seeds, and an error would tell the attacker the PIN is wrong.
3. **Uniformity (the security goal):** `decode(uniform seed)` should be distributed like real
   messages. The attacks measure how badly each DTE misses this.

Minimal example: a DTE for a single digit 0-9.

```python
class DigitDTE(DTE):
    seed_length = 16                          # 128 bits; makes mod bias ~10/2^128
    def encode(self, message, rng=None):
        rng = rng or default_rng()
        r = rng.randrange(2**128 // 10)       # pick one of the many seeds that map to `message`
        return (r * 10 + message).to_bytes(16, "big")
    def decode(self, seed):
        return int.from_bytes(seed, "big") % 10
```

`WeakCardDTE` is exactly this pattern with 10^16 instead of 10. It is not encoded as a plain integer,
because then the real seed would always be < 10^16 while random seeds almost never are; see its
docstring.

Usage:

```python
from dte.weak_card import WeakCardDTE
from framework.he import encrypt, decrypt
from attacks.brute_force import brute_force

dte = WeakCardDTE()
ct = encrypt(dte, "4111111111111111", "4821")
decrypt(dte, ct, "4821")       # '4111111111111111'
decrypt(dte, ct, "0000")       # a decoy, no error
brute_force(ct, dte)           # [('0000', ...), ..., ('9999', ...)]
```

## RSA prime DTE

The RSA DTE works with the same framework as the card DTEs:

```python
from random import Random
from dte.rsa_prime import RSAPrimeDTE, generate_real_prime
from framework.he import encrypt, decrypt

rng = Random(2026)  # Reproducible experiment only; omit rng for secure defaults.
dte = RSAPrimeDTE(1024)
p = generate_real_prime(1024, rng)
ct = encrypt(dte, p, "0042", rng)
assert decrypt(dte, ct, "0042") == p
decoy = decrypt(dte, ct, "0000")  # Another 1024-bit prime candidate; no error.
```

1024-bit primes use 144-byte seeds, so their serialized ciphertexts occupy
176 bytes including salt and nonce. A small-size collision can make a wrong-PIN
candidate equal the real prime; distinct output is not a required guarantee.

**Distribution limitation:** next-prime decoding favours primes with wider
preceding intervals, clipped at the domain boundary. With four-bit primes,
four residues lead to 11 and two to 13: approximately 2/3 versus 1/3. The generator
samples primes independently by rejecting composite odd candidates. Extra seed
bits reduce modulo bias; they do not remove this prime-gap bias. The exhaustive
test temporarily uses a one-byte seed space: all 256 seeds give counts 172 for
11 and 84 for 13. Actual seed sizes are unchanged by that test.

This is a teaching prime-factor encoder, not a production RSA key generator.
SymPy uses probable-prime testing for large integers rather than primality
certificates. Valid prime decoys can still be verified against a public modulus;
the RSA verification attack is a separate component. Tests cover small domains,
framework integration, and a few 1024-bit round trips; they do not perform the
full 10,000-PIN real-size attack.

Public verification keeps every candidate proper factor of N, in input order:

```python
from attacks.rsa_verify import find_real_prime

candidates = [("0000", 17), ("0042", 11), ("1234", 13), ("9999", 11)]
assert find_real_prime(candidates, 143) == [
    ("0042", 11), ("1234", 13), ("9999", 11),
]
```

Finding a valid factor does not necessarily identify the original PIN uniquely.
The verifier tests supplied integer candidates; it does not factor N from scratch.

Run the narrated end-to-end demonstration from the repo root:

```powershell
.\.venv\Scripts\python.exe -m experiments.demo_rsa --bits 16 --seed 2026
```

It generates distinct p/q, encrypts p, enumerates all 10,000 PINs, and checks
candidate divisibility against public N. The reduced-size seed-2026 example has
16-bit factors and a 31-bit modulus: 10 candidate PINs match across both factors.
The true PIN survives, but this toy example does not recover a unique PIN.

For real-size factors, benchmark first and explicitly select the full run:

```powershell
# Optional arithmetic acceleration; SymPy detects it automatically.
.\.venv\Scripts\python.exe -m pip install gmpy2
.\.venv\Scripts\python.exe -m experiments.demo_rsa --bits 1024 --seed 2026 --benchmark-guesses 10 --benchmark-only
.\.venv\Scripts\python.exe -m experiments.demo_rsa --bits 1024 --seed 2026 --output results/rsa-1024-seed-2026.json
```

The first benchmark in our environment estimated about 61 minutes with SymPy's
pure-Python backend; optional gmpy2 2.3.2 reduced the estimate to about 8 minutes
for the same inputs. These are extrapolations from 10 guesses, not full-run
measurements. The original dependencies remain sufficient for correctness.

**Measured full run:** with gmpy2 2.3.2 and seed 2026, all 10,000 guesses took
777.245 seconds (about 13 minutes); public verification took 0.045071 seconds.
The 2048-bit modulus had exactly one matching candidate PIN, `2381`, the true
PIN, and one distinct verified factor. This is one reproducible experiment,
not a guarantee that every trial identifies a unique PIN. The full record is
kept outside the repo at
`../openspec/changes/kee-rsa-and-experiments/rsa-1024-full-seed-2026.json`.

`--output` saves all verified matches, generated demonstration inputs, seed,
timings, software versions, active SymPy backend, Git state, and source checksums.
It refuses to overwrite an existing file. Factor size and actual modulus size
are reported separately: two 1024-bit factors can produce a 2047- or 2048-bit N.
Normal tests use small all-PIN runs; the full real-size enumeration is explicit.

Run the complete AES acceptance comparison:

```powershell
.\.venv\Scripts\python.exe -m experiments.aes_mode_pitfall --seed 2026
```

Measured seed-2026 results, with all 10,000 PINs attempted in each mode:

| Mode | Accepted guesses | Acceptance check |
|---|---:|---|
| CTR | 10000 | None |
| GCM | 1 | Authentication tag |
| CBC + PKCS#7 | 45 | Valid padding |

The function is also available directly:

```python
from experiments.aes_mode_pitfall import count_accepting_pins
assert count_accepting_pins("CTR", seed=2026) == 10000
```

Each mode uses the same seed plaintext, salt, true PIN, and key derivation,
with a suitable separate IV/nonce. Acceptance means the mode's checks pass, not
necessarily that the original plaintext was recovered. Only the expected tag
or padding failure is treated as a rejected guess; programming errors propagate.

GCM's tag rejects wrong keys with overwhelming probability; the count of one
is the observation for this fixture. CBC is weaker as a key check: a random
final block has valid PKCS#7 padding with probability approximately
`1/256 + 1/256**2 + ... + 1/256**16`, about 1/255. That predicts roughly 39
accepted wrong guesses plus the true guess; the actual count varies. Seed 2026
gave 45 total. Neither CBC tests nor the demo assume an exact survivor count.
These rejection checks let an attacker remove decoys before DTE decoding, which
explains the framework's CTR choice. The shared framework remains unchanged.

## Final harness: baseline stage

The harness currently runs two setups through its Python function:

```python
from experiments.success_vs_baseline import run_trials

result = run_trials("baseline", n_trials=3, seed=2026)
print([row["rank"] for row in result["trials"]])  # [4915, 6030, 3450]
control = run_trials("baseline-format", n_trials=3, seed=2026)
```

Both draw synthetic cards from the good DTE, choose uniform PINs, encrypt, and
decrypt under all 10,000 PINs. `baseline` randomly orders equally scored
candidates. `baseline-format` applies the existing format scorer, but every
good-DTE candidate passes, so the same seeded tie-breaking gives the same ranks.
Each control trial records 10,000 survivors at every format stage.

`validate_setup` accepts the following planned configurations without executing
them. Only the first row is runnable at this stage:

| Setup names | DTE choices | Current state |
|---|---|---|
| `baseline`, `baseline-format` | `good` | Runnable, uniform prior only |
| `format`, `pin`, `format-pin` | `weak`, `good` | Defined; integration pending |
| `side-bank`, `side-last4`, `side-bank-last4`, `side-bank-last4-pin` | `good` | Defined; integration pending |
| `wallet-simple`, `wallet-simple-pin`, `wallet-bayes-pin` | `good` | Defined; integration pending |
| `rsa-verify` | `rsa` | Harness integration pending; standalone RSA demo works |

Keyword options are `dte` (default `good`), `prior` (default `uniform`), `k`,
and `rho`. Priors are `uniform`, `calibrated`, or `uniform-tail`; the baseline
controls and planned RSA route require uniform PINs. Wallet defaults are k=2,
rho=1, with allowed k=2/3/5. Only Bayes wallet ranking allows rho below one.
Non-wallet setups reject k/rho. Unknown or incompatible options fail before
encryption; defined future routes raise `NotImplementedError` rather than
silently running a different experiment. The module CLI is a later task.

The result is a plain dictionary: `metadata` records options and the analytical
0.0001 rank-one baseline; `trials` contains one-based trial index, setup, true
four-character PIN, true-PIN rank, and candidate count; `summary` is `None`
until the statistics task. Format controls also include per-stage counts.
No automatic saving or plotting is implemented yet.

The three-trial example has no rank-one successes. This is a mechanics check,
not evidence that success probability is zero: at the 1/10,000 baseline even
1,000 trials expect only 0.1 successes. Use analytical references and, later,
confidence intervals rather than demanding exactly 0.01% from a small sample.

## Randomness rule (reproducibility)

`encrypt(..., rng=None)` and `DTE.encode(..., rng=None)` take an optional `random.Random`-compatible
object. It supplies the salt, the nonce and the DTE's encoding randomness.

- **Experiments MUST pass a seeded `random.Random(seed)`** and record the seed, so results can be
  reproduced exactly.
- **Real usage MUST NOT pass an rng.** The default is `secrets.SystemRandom()` (the OS CSPRNG). A
  seeded `Random` (Mersenne Twister) is predictable, so the salt, the nonce and the encoding are too.

Use only the `random.Random` interface (`randbytes`, `randrange`, `random`). numpy Generators are not
supported, because `integers()` can't draw 128-bit or RSA-size ranges.
