"""
SHA-1 (Secure Hash Algorithm 1) – FIPS 180-4 / RFC 3174, NSA/NIST, 1995.

  * Saída: 160 bits (20 bytes)
  * Bloco: 512 bits (64 bytes), palavras de 32 bits em big-endian
  * Estado: 5 palavras (H0..H4)
  * 80 passos com expansão da mensagem W[t] = ROTL1(W[t-3] ⊕ W[t-8] ⊕ W[t-14] ⊕ W[t-16])

ATENÇÃO: a primeira colisão prática foi publicada em 2017 (SHAttered – Stevens et al.)
e em 2020 foi demonstrada uma colisão com prefixo escolhido (Leurent & Peyrin).
O NIST determinou a retirada do SHA-1 até 31/12/2030. Não use para assinaturas.
"""

from __future__ import annotations

from ._base import MASK32, MerkleDamgard, rotl32


class SHA1(MerkleDamgard):
    name = "sha1"
    digest_size = 20
    block_size = 64
    length_bytes = 8
    byteorder = "big"
    word_bytes = 4
    _IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

    def _compress(self, block: bytes) -> None:
        # 1) Escalonamento da mensagem (message schedule): 16 -> 80 palavras
        W = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(16)]
        for t in range(16, 80):
            W.append(rotl32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1))

        a, b, c, d, e = self._h

        # 2) 80 passos divididos em 4 faixas de 20 com funções e constantes diferentes
        for t in range(80):
            if t < 20:
                f, k = (b & c) | (~b & d), 0x5A827999          # Ch (escolha)
            elif t < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1                   # Parity
            elif t < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC  # Maj (maioria)
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6                   # Parity

            temp = (rotl32(a, 5) + (f & MASK32) + e + k + W[t]) & MASK32
            e, d, c, b, a = d, c, rotl32(b, 30), a, temp

        # 3) Feed-forward
        self._h = [(x + y) & MASK32 for x, y in zip(self._h, (a, b, c, d, e))]


def sha1(data: bytes = b"") -> SHA1:
    return SHA1(data)
