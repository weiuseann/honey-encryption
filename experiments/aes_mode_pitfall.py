"""[STUB] Side demo: why HE must use AES-CTR, not GCM or CBC with padding.

What goes here (about 20 lines):
  Encrypt the same seed with the same weak PIN-derived key under three modes,
  then decrypt with all 10,000 PINs and count how many PINs "succeed":
    - AES-GCM:      only the right PIN passes the tag check -> 1 candidate
    - AES-CBC+PKCS7: most wrong PINs fail the padding check -> a handful
    - AES-CTR:      every PIN succeeds -> 10,000 candidates (what HE needs)
  The point: any integrity or format check on the ciphertext acts as a
  "wrong PIN" oracle and removes HE's protection before the DTE even matters.
"""


def count_accepting_pins(mode: str) -> int:
    raise NotImplementedError


if __name__ == "__main__":
    raise NotImplementedError
