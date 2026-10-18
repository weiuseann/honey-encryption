"""Verify candidate factors using the public RSA modulus, not a secret oracle.

PIN enumeration supplies the candidates; a remainder check identifies valid
factors. This does not factor an arbitrary modulus without those candidates or
break AES. Duplicate factors and both RSA factors can match under multiple PINs,
so finding a factor does not guarantee unique recovery of the original PIN.
"""


def find_real_prime(candidates: list[tuple[str, int]], N: int) -> list[tuple[str, int]]:
    """Keep all proper-divisor candidates in order, including duplicate matches.

    Candidates are integer factors from the DTE; N is the public RSA modulus.
    Modulus checks validate type/range, not compositeness or RSA key structure.
    """
    if isinstance(N, bool) or not isinstance(N, int):
        raise TypeError("N must be an integer RSA modulus")
    if N <= 3:
        raise ValueError("N must be greater than 3")

    return [(pin, p) for pin, p in candidates if 1 < p < N and N % p == 0]
