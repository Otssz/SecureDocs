"""
Família SHA-3 – FIPS 202, NIST, 2015 (algoritmo Keccak – Bertoni, Daemen, Peeters, Van Assche).

Diferente do MD5/SHA-1/SHA-2, o SHA-3 NÃO usa Merkle–Damgård: usa a
CONSTRUÇÃO ESPONJA (sponge construction) sobre a permutação Keccak-f[1600].

  * Estado: 1600 bits = matriz 5×5 de "lanes" de 64 bits
  * O estado é dividido em  r (rate, taxa)  +  c (capacity, capacidade) = 1600
  * Fase de ABSORÇÃO: cada bloco de r bits é combinado (XOR) ao estado, seguido de Keccak-f
  * Fase de ESPREMEDURA (squeeze): lêem-se r bits da saída por vez
  * Segurança contra colisões ≈ c/2 bits; os c bits nunca são expostos

  Variante   r (bits)  c (bits)  Saída
  SHA3-224   1152      448       224
  SHA3-256   1088      512       256
  SHA3-384   832       768       384
  SHA3-512   576       1024      512
  SHAKE128   1344      256       variável (XOF)
  SHAKE256   1088      512       variável (XOF)

Como os c bits de capacidade ficam ocultos, o SHA-3 é naturalmente imune ao
ataque de extensão de comprimento que afeta MD5, SHA-1 e SHA-2.

As constantes de rodada (RC) e os deslocamentos de rotação (ρ) são GERADOS a
partir de sua definição no FIPS 202 (LFSR e sequência triangular).
"""

from __future__ import annotations

from ._base import MASK64, HashBase, _to_bytes, rotl64


# ---------------------------------------------------------------------------
# Constantes geradas pela definição (FIPS 202, seção 3.2)
# ---------------------------------------------------------------------------
def _rc_bit(t: int) -> int:
    """Algoritmo 5 do FIPS 202: saída do LFSR x^8 + x^6 + x^5 + x^4 + 1."""
    if t % 255 == 0:
        return 1
    R = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(1, t % 255 + 1):
        R = [0] + R
        R[0] ^= R[8]
        R[4] ^= R[8]
        R[5] ^= R[8]
        R[6] ^= R[8]
        R = R[:8]
    return R[0]


def _round_constants(n_rounds: int = 24) -> list[int]:
    rcs = []
    for ir in range(n_rounds):
        rc = 0
        for j in range(7):                       # l = 6  ->  posições 2^j - 1
            rc |= _rc_bit(j + 7 * ir) << ((1 << j) - 1)
        rcs.append(rc)
    return rcs


def _rho_offsets() -> list[int]:
    """Deslocamentos da etapa ρ: (t+1)(t+2)/2 mod 64 ao longo da trajetória (x,y)->(y,2x+3y)."""
    off = [0] * 25
    x, y = 1, 0
    for t in range(24):
        off[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return off


RC = _round_constants()
RHO = _rho_offsets()


def keccak_f1600(A: list[int]) -> list[int]:
    """
    Permutação Keccak-f[1600]: 24 rodadas de θ, ρ, π, χ, ι.
    ``A`` é uma lista de 25 inteiros de 64 bits, índice = x + 5*y.
    """
    A = list(A)
    for rnd in range(24):
        # θ (theta) – difusão por paridade das colunas
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ rotl64(C[(x + 1) % 5], 1) for x in range(5)]
        A = [A[i] ^ D[i % 5] for i in range(25)]

        # ρ (rho) e π (pi) – rotação de cada lane e permutação das posições
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[x + 5 * y], RHO[x + 5 * y])

        # χ (chi) – única etapa NÃO-linear
        A = [B[i] ^ ((~B[(i % 5 + 1) % 5 + 5 * (i // 5)]) & B[(i % 5 + 2) % 5 + 5 * (i // 5)])
             for i in range(25)]
        A = [a & MASK64 for a in A]

        # ι (iota) – quebra a simetria entre as rodadas
        A[0] ^= RC[rnd]
    return A


class _Sponge(HashBase):
    """Construção esponja genérica com Keccak-f[1600]."""

    rate: int = 0            # em bytes
    suffix: int = 0x06       # sufixo de domínio: 0x06 = SHA-3, 0x1F = SHAKE

    def __init__(self, data: bytes = b""):
        self._state = [0] * 25
        self._buffer = b""
        self.block_size = self.rate
        if data:
            self.update(data)

    def _absorb_block(self, block: bytes) -> None:
        for i in range(self.rate // 8):
            self._state[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        self._state = keccak_f1600(self._state)

    def update(self, data) -> "_Sponge":
        buf = self._buffer + _to_bytes(data)
        r = self.rate
        n = len(buf) // r
        for i in range(n):
            self._absorb_block(buf[i * r:(i + 1) * r])
        self._buffer = buf[n * r:]
        return self

    def _squeeze(self, length: int) -> bytes:
        clone = self.copy()
        # Padding pad10*1 com sufixo de domínio
        pad = bytearray(clone.rate - len(clone._buffer))
        pad[0] ^= clone.suffix
        pad[-1] ^= 0x80
        clone._absorb_block(clone._buffer + bytes(pad))
        # Espremedura
        out = b""
        while True:
            out += b"".join(lane.to_bytes(8, "little") for lane in clone._state[: clone.rate // 8])
            if len(out) >= length:
                return out[:length]
            clone._state = keccak_f1600(clone._state)


class _SHA3(_Sponge):
    suffix = 0x06

    def digest(self) -> bytes:
        return self._squeeze(self.digest_size)


class SHA3_224(_SHA3):
    name, digest_size, rate = "sha3_224", 28, 144


class SHA3_256(_SHA3):
    name, digest_size, rate = "sha3_256", 32, 136


class SHA3_384(_SHA3):
    name, digest_size, rate = "sha3_384", 48, 104


class SHA3_512(_SHA3):
    name, digest_size, rate = "sha3_512", 64, 72


class _SHAKE(_Sponge):
    """XOF – Extendable Output Function: o tamanho da saída é escolhido pelo usuário."""
    suffix = 0x1F
    digest_size = 0

    def digest(self, length: int) -> bytes:  # type: ignore[override]
        return self._squeeze(length)

    def hexdigest(self, length: int) -> str:  # type: ignore[override]
        return self.digest(length).hex()


class SHAKE128(_SHAKE):
    name, rate = "shake_128", 168


class SHAKE256(_SHAKE):
    name, rate = "shake_256", 136


def sha3_224(data: bytes = b"") -> SHA3_224: return SHA3_224(data)
def sha3_256(data: bytes = b"") -> SHA3_256: return SHA3_256(data)
def sha3_384(data: bytes = b"") -> SHA3_384: return SHA3_384(data)
def sha3_512(data: bytes = b"") -> SHA3_512: return SHA3_512(data)
def shake_128(data: bytes = b"") -> SHAKE128: return SHAKE128(data)
def shake_256(data: bytes = b"") -> SHAKE256: return SHAKE256(data)
