"""
MD5 (Message-Digest Algorithm 5) – RFC 1321, Ronald Rivest, 1992.

  * Saída: 128 bits (16 bytes)
  * Bloco: 512 bits (64 bytes), palavras de 32 bits em little-endian
  * Estado: 4 palavras (A, B, C, D)
  * 64 passos, organizados em 4 rodadas de 16 passos (funções F, G, H, I)

ATENÇÃO: o MD5 está QUEBRADO quanto à resistência a colisões (Wang et al., 2004).
Colisões são geradas em segundos num computador comum. Use apenas para fins
didáticos ou como checksum contra erros acidentais – nunca para segurança.
"""

from __future__ import annotations

import math

from ._base import MASK32, MerkleDamgard, rotl32

# Constantes K[i] = floor(|sen(i + 1)| * 2^32)  ("nothing-up-my-sleeve numbers")
K = [int(abs(math.sin(i + 1)) * 2 ** 32) & MASK32 for i in range(64)]

# Quantidade de bits da rotação em cada passo
S = ([7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 +
     [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4)


class MD5(MerkleDamgard):
    name = "md5"
    digest_size = 16
    block_size = 64
    length_bytes = 8
    byteorder = "little"
    word_bytes = 4
    _IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

    def _compress(self, block: bytes) -> None:
        # 16 palavras de 32 bits em little-endian
        M = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(16)]
        a, b, c, d = self._h

        for i in range(64):
            if i < 16:                      # Rodada 1: F(B,C,D) = (B∧C) ∨ (¬B∧D)
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:                    # Rodada 2: G(B,C,D) = (B∧D) ∨ (C∧¬D)
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:                    # Rodada 3: H(B,C,D) = B ⊕ C ⊕ D
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:                           # Rodada 4: I(B,C,D) = C ⊕ (B ∨ ¬D)
                f = c ^ (b | (~d & MASK32))
                g = (7 * i) % 16

            f = (f + a + K[i] + M[g]) & MASK32
            a, d, c = d, c, b
            b = (b + rotl32(f, S[i])) & MASK32

        # Feed-forward (Davies–Meyer): soma o estado anterior
        self._h = [(x + y) & MASK32 for x, y in zip(self._h, (a, b, c, d))]


def md5(data: bytes = b"") -> MD5:
    """Atalho no estilo ``hashlib.md5``."""
    return MD5(data)
