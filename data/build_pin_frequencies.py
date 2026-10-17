"""Build data/pin_frequencies.csv from the DataGenetics figures plus our tier model.

Run from the repo root:  python data/build_pin_frequencies.py

Source: Nick Berry, "PIN number analysis", DataGenetics, September 2012,
https://datagenetics.com/blog/september32012/index.html (about 3.4 million 4-digit passwords used as
a proxy for PINs). See data/README.md for which numbers are published and which are our assumption.

Model ("calibrated", the main one):
  - the published top 20 and bottom 21 PINs get their published frequencies;
  - a "pattern" tier (valid MMDD dates, years 1900-2029, repeated pairs ABAB) gets k*b each;
  - every other PIN gets b each.
  b and k are solved from two published facts: the total is 1, and the 426 most popular PINs cover
  50%. Which PINs count as "patterns" is our assumption, not published data.

Model ("uniform_tail", sensitivity check): same published top 20 and bottom 21, the remaining mass
spread uniformly over all other PINs.
"""

import calendar
import csv
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent
CALIBRATED_PATH = DATA_DIR / "pin_frequencies.csv"
UNIFORM_TAIL_PATH = DATA_DIR / "pin_frequencies_uniform_tail.csv"

# Published: DataGenetics top-20 table (percent).
TOP_20 = {
    "1234": 10.713, "1111": 6.016, "0000": 1.881, "1212": 1.197, "7777": 0.745,
    "1004": 0.616, "2000": 0.613, "4444": 0.526, "2222": 0.516, "6969": 0.512,
    "9999": 0.451, "3333": 0.419, "5555": 0.395, "6666": 0.391, "1122": 0.366,
    "1313": 0.304, "8888": 0.303, "4321": 0.293, "2001": 0.290, "1010": 0.285,
}

# Published: DataGenetics "least popular" table, ranks #9980-#10000 (21 rows, percent).
BOTTOM_21 = {
    "8557": 0.001191, "9047": 0.001161, "8438": 0.001161, "0439": 0.001161, "9539": 0.001161,
    "8196": 0.001131, "7063": 0.001131, "6093": 0.001131, "6827": 0.001101, "7394": 0.001101,
    "0859": 0.001072, "8957": 0.001042, "9480": 0.001042, "6793": 0.001012, "8398": 0.000982,
    "0738": 0.000982, "7637": 0.000953, "6835": 0.000953, "9629": 0.000953, "8093": 0.000893,
    "8068": 0.000744,
}

# Published: "the 50% cumulative chance threshold is passed at just 426 codes".
HALF_MASS_RANK = 426

ALL_PINS = [f"{i:04d}" for i in range(10_000)]


def pattern_pins() -> set[str]:
    """Our assumption: PINs people pick because they are memorable, beyond the published top 20.

    The article names these patterns (years, MMDD dates, repeated couplets) but gives no numbers.
    """
    dates = {f"{m:02d}{d:02d}" for m in range(1, 13) for d in range(1, calendar.monthrange(2000, m)[1] + 1)}
    years = {str(y) for y in range(1900, 2030)}
    couplets = {f"{a:02d}" * 2 for a in range(100)}
    return (dates | years | couplets) - TOP_20.keys() - BOTTOM_21.keys()


def _published() -> dict[str, float]:
    return {pin: pct / 100 for pin, pct in {**TOP_20, **BOTTOM_21}.items()}


def calibrated_model() -> tuple[dict[str, float], dict[str, str]]:
    freqs = _published()
    tiers = {pin: "published" for pin in freqs}
    patterns = pattern_pins()
    rest = [p for p in ALL_PINS if p not in freqs and p not in patterns]

    top_mass = sum(TOP_20.values()) / 100
    remaining = 1 - sum(freqs.values())
    n_fill = HALF_MASS_RANK - len(TOP_20)  # pattern PINs needed to fill ranks 21..426
    if len(patterns) < n_fill:
        raise ValueError("pattern tier too small to fill ranks up to the 50% point")

    # Ranks 21..426 are all pattern PINs (they are the next most likely), so:
    #   n_fill * kb = 0.5 - top_mass                       (published 50% point)
    #   len(patterns) * kb + len(rest) * b = remaining     (total probability is 1)
    kb = (0.5 - top_mass) / n_fill
    b = (remaining - len(patterns) * kb) / len(rest)
    # Sanity: patterns must sit between the published top 20 and the ordinary PINs.
    if not (b < kb < min(TOP_20.values()) / 100) or b <= 0:
        raise ValueError(f"calibration out of range: b={b}, kb={kb}")

    for p in patterns:
        freqs[p], tiers[p] = kb, "pattern"
    for p in rest:
        freqs[p], tiers[p] = b, "base"
    return freqs, tiers


def uniform_tail_model() -> tuple[dict[str, float], dict[str, str]]:
    freqs = _published()
    tiers = {pin: "published" for pin in freqs}
    rest = [p for p in ALL_PINS if p not in freqs]
    b = (1 - sum(freqs.values())) / len(rest)
    for p in rest:
        freqs[p], tiers[p] = b, "base"
    return freqs, tiers


def cumulative(freqs: dict[str, float], n: int, from_bottom: bool = False) -> float:
    ordered = sorted(freqs.values(), reverse=not from_bottom)
    return sum(ordered[:n])


def write_csv(path: Path, freqs: dict[str, float], tiers: dict[str, str]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pin", "frequency", "tier"])
        for pin in ALL_PINS:
            w.writerow([pin, f"{freqs[pin]:.10g}", tiers[pin]])


def main() -> None:
    for name, model, path in [("calibrated", calibrated_model, CALIBRATED_PATH),
                              ("uniform_tail", uniform_tail_model, UNIFORM_TAIL_PATH)]:
        freqs, tiers = model()
        write_csv(path, freqs, tiers)
        print(f"{name}: wrote {path.name}")
        print(f"  top 61    {cumulative(freqs, 61):.1%}   (published: about 33%)")
        print(f"  top 426   {cumulative(freqs, 426):.1%}   (published: 50%)")
        print(f"  bottom 4200 {cumulative(freqs, 4200, from_bottom=True):.1%}   (published: < 10.7%)")


if __name__ == "__main__":
    main()
