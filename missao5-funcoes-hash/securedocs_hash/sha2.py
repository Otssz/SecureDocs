"""
Família SHA-2 – FIPS 180-4, NSA/NIST, 2001.

  Variante       Palavra  Bloco     Passos  Saída
  SHA-224        32 bits  512 bits  64      224 bits
  SHA-256        32 bits  512 bits  64      256 bits
  SHA-384        64 bits  1024 bits 80      384 bits
  SHA-512        64 bits  1024 bits 80      512 bits
  SHA-512/224    64 bits  1024 bits 80      224 bits
  SHA-512/256    64 bits  1024 bits 80      256 bits

Todas usam a construção de Merkle–Damgård com compressão de Davies–Meyer.

Diferencial didático desta implementação: as constantes NÃO foram copiadas
de uma tabela. Elas são CALCULADAS a partir de sua definição na norma
(partes fracionárias das raízes quadradas e cúbicas dos primeiros números primos).
Isso mostra que são "nothing-up-my-sleeve numbers" – números sem backdoor escondido.
"""

from __future__ import annotations

from ._base import MASK32, MASK64, MerkleDamgard, rotr32, rotr64


# ---------------------------------------------------------------------------
# Geração das constantes a partir da definição do FIPS 180-4
# ---------------------------------------------------------------------------
def _primes(n: int) -> list[int]:
    ps, k = [], 2
    while len(ps) < n:
        if all(k % p for p in ps if p * p <= k):
            ps.append(k)
        k += 1
    return ps


def _icbrt(n: int) -> int:
    """Raiz cúbica inteira (piso) por método de Newton – precisão arbitrária."""
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            break
        x = y
    while x ** 3 > n:
        x -= 1
    while (x + 1) ** 3 <= n:
        x += 1
    return x


def _isqrt(n: int) -> int:
    import math
    return math.isqrt(n)


def _frac_sqrt(p: int, bits: int) -> int:
    """Primeiros ``bits`` bits da parte fracionária de sqrt(p)."""
    return _isqrt(p << (2 * bits)) & ((1 << bits) - 1)


def _frac_cbrt(p: int, bits: int) -> int:
    """Primeiros ``bits`` bits da parte fracionária de cbrt(p)."""
    return _icbrt(p << (3 * bits)) & ((1 << bits) - 1)


_P = _primes(80)

# Constantes de rodada
K256 = [_frac_cbrt(p, 32) for p in _P[:64]]        # 64 constantes de 32 bits
K512 = [_frac_cbrt(p, 64) for p in _P[:80]]        # 80 constantes de 64 bits

# Valores iniciais (IV)
IV256 = tuple(_frac_sqrt(p, 32) for p in _P[:8])                    # primos 2..19
IV512 = tuple(_frac_sqrt(p, 64) for p in _P[:8])
IV384 = tuple(_frac_sqrt(p, 64) for p in _P[8:16])                  # primos 23..53
IV224 = tuple(_frac_sqrt(p, 64) & MASK32 for p in _P[8:16])         # 2º bloco de 32 bits


# ---------------------------------------------------------------------------
# SHA-256 / SHA-224 (palavras de 32 bits)
# ---------------------------------------------------------------------------
class SHA256(MerkleDamgard):
    name = "sha256"
    digest_size = 32
    block_size = 64
    length_bytes = 8
    byteorder = "big"
    word_bytes = 4
    _IV = IV256

    def _compress(self, block: bytes) -> None:
        # Escalonamento: 16 palavras da mensagem -> 64 palavras
        W = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(16)]
        for t in range(16, 64):
            s0 = rotr32(W[t - 15], 7) ^ rotr32(W[t - 15], 18) ^ (W[t - 15] >> 3)    # σ0
            s1 = rotr32(W[t - 2], 17) ^ rotr32(W[t - 2], 19) ^ (W[t - 2] >> 10)     # σ1
            W.append((W[t - 16] + s0 + W[t - 7] + s1) & MASK32)

        a, b, c, d, e, f, g, h = self._h
        for t in range(64):
            S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)       # Σ1
            ch = (e & f) ^ (~e & g)                                 # Ch(e,f,g)
            T1 = (h + S1 + ch + K256[t] + W[t]) & MASK32
            S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)       # Σ0
            maj = (a & b) ^ (a & c) ^ (b & c)                       # Maj(a,b,c)
            T2 = (S0 + maj) & MASK32
            h, g, f, e, d, c, b, a = g, f, e, (d + T1) & MASK32, c, b, a, (T1 + T2) & MASK32

        self._h = [(x + y) & MASK32 for x, y in zip(self._h, (a, b, c, d, e, f, g, h))]


class SHA224(SHA256):
    """Mesmo núcleo do SHA-256, IV diferente e saída truncada em 224 bits."""
    name = "sha224"
    digest_size = 28
    _IV = IV224


# ---------------------------------------------------------------------------
# SHA-512 / SHA-384 / SHA-512/t (palavras de 64 bits)
# ---------------------------------------------------------------------------
class SHA512(MerkleDamgard):
    name = "sha512"
    digest_size = 64
    block_size = 128
    length_bytes = 16
    byteorder = "big"
    word_bytes = 8
    _IV = IV512

    def _compress(self, block: bytes) -> None:
        W = [int.from_bytes(block[8 * i:8 * i + 8], "big") for i in range(16)]
        for t in range(16, 80):
            s0 = rotr64(W[t - 15], 1) ^ rotr64(W[t - 15], 8) ^ (W[t - 15] >> 7)
            s1 = rotr64(W[t - 2], 19) ^ rotr64(W[t - 2], 61) ^ (W[t - 2] >> 6)
            W.append((W[t - 16] + s0 + W[t - 7] + s1) & MASK64)

        a, b, c, d, e, f, g, h = self._h
        for t in range(80):
            S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
            ch = (e & f) ^ (~e & g)
            T1 = (h + S1 + ch + K512[t] + W[t]) & MASK64
            S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            T2 = (S0 + maj) & MASK64
            h, g, f, e, d, c, b, a = g, f, e, (d + T1) & MASK64, c, b, a, (T1 + T2) & MASK64

        self._h = [(x + y) & MASK64 for x, y in zip(self._h, (a, b, c, d, e, f, g, h))]


class SHA384(SHA512):
    name = "sha384"
    digest_size = 48
    _IV = IV384


def _sha512t_iv(t: int) -> tuple:
    """
    Função geradora de IV do SHA-512/t (FIPS 180-4, seção 5.3.6):
    calcula SHA-512 da string "SHA-512/t" usando como IV o IV do SHA-512
    com cada palavra XOR 0xa5a5a5a5a5a5a5a5.
    """
    gen = SHA512(_state=[h ^ 0xA5A5A5A5A5A5A5A5 for h in IV512])
    gen.update(f"SHA-512/{t}".encode())
    return tuple(SHA512.state_from_digest(gen.digest()))


class SHA512_224(SHA512):
    name = "sha512_224"
    digest_size = 28
    _IV = _sha512t_iv(224)


class SHA512_256(SHA512):
    name = "sha512_256"
    digest_size = 32
    _IV = _sha512t_iv(256)


def sha224(data: bytes = b"") -> SHA224: return SHA224(data)
def sha256(data: bytes = b"") -> SHA256: return SHA256(data)
def sha384(data: bytes = b"") -> SHA384: return SHA384(data)
def sha512(data: bytes = b"") -> SHA512: return SHA512(data)
def sha512_224(data: bytes = b"") -> SHA512_224: return SHA512_224(data)
def sha512_256(data: bytes = b"") -> SHA512_256: return SHA512_256(data)
