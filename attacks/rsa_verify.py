"""[STUB] Public verification: the RSA public key identifies the real prime.

What goes here (Scenario B):
  The public modulus N = p*q is, by definition, public. For each brute-force
  candidate p', check N % p' == 0. Only the real p divides N, so the real
  candidate is found with certainty, however perfect the DTE's decoys are.

Framing (agreed): this is NOT a break of RSA or AES. It shows that honey
encryption can't hide a secret that can be verified against public
information. A decoy only helps if the attacker has no way to test it.
"""


def find_real_prime(candidates: list[tuple[str, int]], N: int) -> list[tuple[str, int]]:
    """Return the candidates whose prime divides N (expected: exactly the real one)."""
    raise NotImplementedError
