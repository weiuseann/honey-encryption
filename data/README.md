# data/

Placeholder files. Each currently holds only its header row and should be filled in before the
good DTE and the attacks are built.

## bin_list.csv

Used by `dte/good_card.py`, `attacks/format_filter.py` and `attacks/side_info.py`.

| column    | meaning                                                         |
|-----------|-----------------------------------------------------------------|
| `bin`     | Issuer prefix (first 6 or 8 digits)                             |
| `network` | `visa`, `mastercard`, ...                                       |
| `bank`    | Issuing bank, e.g. `DBS`                                        |
| `product` | Card product name                                               |
| `weight`  | Relative frequency, used by the DTE's inverse-CDF sampling      |

Record the source of the BINs and of the weights here when you fill it in. If the weights are
estimates, say so; the chi-square test only checks the DTE against these weights.

## pin_frequencies.csv

Used by `attacks/pin_ranking.py` and to sample non-uniform PINs in experiments.

| column      | meaning                                                  |
|-------------|----------------------------------------------------------|
| `pin`       | 4-digit string, keep leading zeros (`0000`)              |
| `frequency` | Fraction of users choosing this PIN (should sum to ~1)   |

Source: Nick Berry, "PIN number analysis", DataGenetics (2012),
https://datagenetics.com/blog/september32012/index.html. Cite this in the slides.
The published data gives the most common PINs exactly. For the rest, describe in this file how the
remaining probability mass is spread.
