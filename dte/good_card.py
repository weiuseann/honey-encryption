"""Good credit card DTE: decoys follow the same distribution as the BIN table.

A card number is built in four steps:
    network -> BIN (6 digits, from data/bin_list.csv) -> 9 middle digits -> Luhn check digit
so every decoded card is 16 digits, starts with a BIN from the table and passes the Luhn check. The
format filter attack therefore cannot rule out any decoy.

Inverse-CDF with integer weights (no floats, so no rounding):
  Each BIN has an integer weight w_i. Lay out W = sum(w_i) "slots" in a row and give BIN i the block
  [start_i, start_i + w_i). Rows are sorted by network, so each network's BINs form one contiguous
  block whose size is the network's total weight. Landing on a slot picks the network and then the
  BIN, in a single lookup. A card is then one integer

      u = slot * 10^9 + middle,      0 <= u < M = W * 10^9

  and, as in the weak DTE, we hide u inside a 128-bit seed:

      encode(card) = r * M + u    (random slot inside the card's BIN block, random r < 2^128 // M)
      decode(seed) = int(seed) mod M, then split u back into (slot, middle)

  Exactness: everything is integer arithmetic, so decode(encode(m)) == m by construction. BIN i owns
  exactly w_i of the W slots, so P(BIN i) = w_i / W with no approximation error.

  Uniformity: 2^128 is not a multiple of M, so the reduction mod M gives a few values of u one extra
  seed. The relative bias is at most M / 2^128. With our table (W = 1000, M = 10^12) that is about
  3e-27. The same bound limits the attacker's only other clue: encode never outputs a seed at or above
  (2^128 // M) * M, and a random seed lands there with probability below M / 2^128.

What this DTE does NOT model (an attacker with a better model of real cards can exploit it):
  the weights are our assumption, middle digits are uniform although issuers allocate account ranges
  unevenly, and BINs are 6 digits although Visa and Mastercard moved to 8-digit BINs in 2022.
"""

import bisect
import csv
from dataclasses import dataclass
from pathlib import Path
from random import Random

from dte.base import DTE, default_rng
from dte.luhn import is_luhn_valid, luhn_check_digit

BIN_PATH = Path(__file__).resolve().parent.parent / "data" / "bin_list.csv"

N_DIGITS = 16
BIN_DIGITS = 6
MIDDLE_DIGITS = N_DIGITS - BIN_DIGITS - 1  # 9; the last digit is the Luhn check digit
MIDDLE_SPACE = 10**MIDDLE_DIGITS

# Only 16-digit networks: Amex (15 digits) and other lengths don't fit the 16-digit message format.
NETWORK_PREFIXES = {
    "visa": lambda b: b.startswith("4"),
    "mastercard": lambda b: 51 <= int(b[:2]) <= 55 or 222100 <= int(b) <= 272099,
}


@dataclass(frozen=True)
class BinEntry:
    bin: str
    network: str
    bank: str
    product: str
    weight: int
    confidence: str = "illustrative"


def load_bins(path: Path = BIN_PATH) -> list[BinEntry]:
    with open(path, newline="") as f:
        return [
            BinEntry(
                bin=row["bin"],
                network=row["network"],
                bank=row["bank"],
                product=row["product"],
                weight=int(row["weight"]),
                confidence=row["confidence"],
            )
            for row in csv.DictReader(f)
        ]


def _check_table(entries: list[BinEntry]) -> None:
    if not entries:
        raise ValueError("BIN table is empty")
    seen = set()
    for e in entries:
        if len(e.bin) != BIN_DIGITS or not e.bin.isdigit():
            raise ValueError(f"BIN must be {BIN_DIGITS} digits: {e.bin!r}")
        if e.bin in seen:
            # A duplicate would make the BIN -> interval mapping ambiguous, breaking the round trip.
            raise ValueError(f"duplicate BIN {e.bin}")
        seen.add(e.bin)
        if e.network not in NETWORK_PREFIXES:
            raise ValueError(f"unsupported network {e.network!r} for BIN {e.bin}")
        if not NETWORK_PREFIXES[e.network](e.bin):
            raise ValueError(f"BIN {e.bin} is not a {e.network} prefix")
        if e.weight <= 0:
            # A zero-weight BIN would own no slots, so a real card with it could not be encoded.
            raise ValueError(f"weight must be a positive integer for BIN {e.bin}")


def bank_shares(bins: list[BinEntry]) -> dict[str, float]:
    """Each bank's share of the total BIN weight = P(a decoded card is from that bank)."""
    total = sum(e.weight for e in bins)
    shares: dict[str, float] = {}
    for e in bins:
        shares[e.bank] = shares.get(e.bank, 0) + e.weight / total
    return shares


class GoodCardDTE(DTE):
    seed_length = 16  # 128 bits, same as the weak DTE, so ciphertext length can't tell them apart

    def __init__(self, bins: list[BinEntry] | None = None):
        entries = load_bins() if bins is None else list(bins)
        _check_table(entries)
        # Sorting by network makes each network one contiguous block of slots (network -> BIN).
        self.bins = sorted(entries, key=lambda e: (e.network, e.bin))
        self.starts = []  # starts[i] = first slot owned by bins[i]
        total = 0
        for e in self.bins:
            self.starts.append(total)
            total += e.weight
        self.total_weight = total
        self._index = {e.bin: i for i, e in enumerate(self.bins)}
        self._modulus = total * MIDDLE_SPACE
        self._max_r = 2 ** (8 * self.seed_length) // self._modulus
        # Keep the bias bound M / 2^128 below 2^-64 even if someone grows the table or its weights.
        if self._max_r < 2**64:
            raise ValueError("total weight too large for a 128-bit seed")

    def network_weights(self) -> dict[str, int]:
        weights: dict[str, int] = {}
        for e in self.bins:
            weights[e.network] = weights.get(e.network, 0) + e.weight
        return weights

    def encode(self, message: str, rng: Random | None = None) -> bytes:
        if not isinstance(message, str) or len(message) != N_DIGITS or not message.isdigit():
            raise ValueError(f"expected a {N_DIGITS}-digit string, got {message!r}")
        if not is_luhn_valid(message):
            raise ValueError(f"card fails the Luhn check: {message}")
        i = self._index.get(message[:BIN_DIGITS])
        if i is None:
            raise ValueError(f"BIN {message[:BIN_DIGITS]} is not in the BIN table")
        rng = rng or default_rng()
        # Pick a random slot inside this BIN's block rather than always its first slot. Otherwise the
        # real seed would sit on a block boundary, which a random seed rarely does.
        slot = self.starts[i] + rng.randrange(self.bins[i].weight)
        u = slot * MIDDLE_SPACE + int(message[BIN_DIGITS:-1])
        r = rng.randrange(self._max_r)
        return (r * self._modulus + u).to_bytes(self.seed_length, "big")

    def decode(self, seed: bytes) -> str:
        # Total function: every integer mod M is a valid (slot, middle) pair, every slot belongs to
        # some BIN, and the check digit is computed rather than read, so the output is always valid.
        u = int.from_bytes(seed, "big") % self._modulus
        slot, middle = divmod(u, MIDDLE_SPACE)
        i = bisect.bisect_right(self.starts, slot) - 1  # last block starting at or before slot
        partial = self.bins[i].bin + f"{middle:0{MIDDLE_DIGITS}d}"
        return partial + luhn_check_digit(partial)

    def sample(self, rng: Random | None = None) -> str:
        """Draw a card from the DTE's own distribution by decoding a random seed.

        Experiments use this to generate "real" cards, so the real-card distribution matches the
        DTE exactly and the 1/10,000 matched-DTE baseline holds.
        """
        rng = rng or default_rng()
        return self.decode(rng.randbytes(self.seed_length))
