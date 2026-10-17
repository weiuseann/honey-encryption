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
| `dte/rsa_prime.py` | stub | next-prime DTE for real-size RSA primes |
| `attacks/brute_force.py` | done | decrypt under all 10,000 PINs |
| `attacks/format_filter.py` | done | Luhn / prefix / BIN filters |
| `attacks/pin_ranking.py` | done | DataGenetics PIN popularity |
| `attacks/ranking.py` | done | `order_by_score` (random tie-break), `rank_of` (shared) |
| `attacks/side_info.py` | done | known bank, known last 4 digits (combine with PIN ranking) |
| `attacks/two_card.py` | stub | two cards under one PIN |
| `attacks/rsa_verify.py` | stub | `N % p == 0` |
| `experiments/card_pairs.py` | stub | correlated real-card-pair generator |
| `experiments/success_vs_baseline.py` | stub | main results: rank / success vs 1/10,000 |
| `experiments/aes_mode_pitfall.py` | stub | GCM/CBC vs CTR side demo |
| `experiments/demo_card_attacks.py` | done | real card's rank under format filter / PIN ranking / side info |
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

## Randomness rule (reproducibility)

`encrypt(..., rng=None)` and `DTE.encode(..., rng=None)` take an optional `random.Random`-compatible
object. It supplies the salt, the nonce and the DTE's encoding randomness.

- **Experiments MUST pass a seeded `random.Random(seed)`** and record the seed, so results can be
  reproduced exactly.
- **Real usage MUST NOT pass an rng.** The default is `secrets.SystemRandom()` (the OS CSPRNG). A
  seeded `Random` (Mersenne Twister) is predictable, so the salt, the nonce and the encoding are too.

Use only the `random.Random` interface (`randbytes`, `randrange`, `random`). numpy Generators are not
supported, because `integers()` can't draw 128-bit or RSA-size ranges.
