"""
Infraestrutura comum às funções hash da biblioteca.

Contém:
  * operações de bits (rotações) usadas pelos algoritmos;
  * a classe ``HashBase``, que define a mesma interface do módulo ``hashlib``
    (update / digest / hexdigest / copy);
  * a classe ``MerkleDamgard``, que implementa a construção de Merkle–Damgård
    (buffer de blocos, preenchimento/padding e campo de comprimento), usada por
    MD5, SHA-1 e pela família SHA-2.

Projeto SecureDocs – Missão 5 (Funções Hash).
"""

from __future__ import annotations

import copy as _copy

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF


def rotl32(x: int, n: int) -> int:
    """Rotação circular à esquerda de uma palavra de 32 bits."""
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def rotr32(x: int, n: int) -> int:
    """Rotação circular à direita de uma palavra de 32 bits."""
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def rotr64(x: int, n: int) -> int:
    """Rotação circular à direita de uma palavra de 64 bits."""
    x &= MASK64
    return ((x >> n) | (x << (64 - n))) & MASK64


def rotl64(x: int, n: int) -> int:
    """Rotação circular à esquerda de uma palavra de 64 bits."""
    x &= MASK64
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _to_bytes(data) -> bytes:
    if isinstance(data, str):
        raise TypeError("Strings devem ser codificadas antes do hash (ex.: texto.encode('utf-8'))")
    return bytes(data)


class HashBase:
    """Interface comum (compatível com ``hashlib``)."""

    name: str = "base"
    digest_size: int = 0   # tamanho da saída em bytes
    block_size: int = 0    # tamanho do bloco interno em bytes

    def update(self, data) -> "HashBase":  # pragma: no cover - abstrato
        raise NotImplementedError

    def digest(self) -> bytes:  # pragma: no cover - abstrato
        raise NotImplementedError

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "HashBase":
        return _copy.deepcopy(self)

    def __repr__(self) -> str:
        return f"<{self.name} objeto hash>"


class MerkleDamgard(HashBase):
    """
    Construção de Merkle–Damgård genérica.

    A mensagem é dividida em blocos de ``block_size`` bytes. Cada bloco é
    processado pela função de compressão ``_compress`` que atualiza o estado
    interno (``self._h``). No final, a mensagem é preenchida com:

        1 bit '1'  ->  bits '0' até sobrar ``length_bytes`` no bloco
        ->  comprimento original da mensagem em bits

    Subclasses definem: ``_IV``, ``block_size``, ``digest_size``,
    ``length_bytes`` (8 ou 16), ``byteorder`` ('big' ou 'little'),
    ``word_bytes`` (4 ou 8) e o método ``_compress(bloco)``.
    """

    _IV: tuple = ()
    length_bytes: int = 8
    byteorder: str = "big"
    word_bytes: int = 4

    def __init__(self, data: bytes = b"", *, _state=None, _length: int = 0):
        # _state/_length permitem retomar o hash a partir de um estado conhecido
        # (usado no ataque de extensão de comprimento – ver attacks.py).
        self._h = list(_state) if _state is not None else list(self._IV)
        self._buffer = b""
        self._length = _length          # nº de bytes já processados
        if data:
            self.update(data)

    # ------------------------------------------------------------------ API
    def update(self, data) -> "MerkleDamgard":
        data = _to_bytes(data)
        self._length += len(data)
        buf = self._buffer + data
        bs = self.block_size
        n_full = len(buf) // bs
        for i in range(n_full):
            self._compress(buf[i * bs:(i + 1) * bs])
        self._buffer = buf[n_full * bs:]
        return self

    def digest(self) -> bytes:
        clone = self.copy()                 # digest() não altera o objeto
        clone._finalize()
        out = b"".join(w.to_bytes(self.word_bytes, self.byteorder) for w in clone._h)
        return out[: self.digest_size]

    # ------------------------------------------------------------ padding
    @classmethod
    def padding(cls, message_length: int) -> bytes:
        """Retorna os bytes de preenchimento para uma mensagem de ``message_length`` bytes."""
        bs, lb = cls.block_size, cls.length_bytes
        pad = b"\x80"
        pad += b"\x00" * ((bs - lb - (message_length + 1) % bs) % bs)
        pad += ((message_length * 8) % (1 << (8 * lb))).to_bytes(lb, cls.byteorder)
        return pad

    def _finalize(self) -> None:
        tail = self._buffer + self.padding(self._length)
        bs = self.block_size
        for i in range(0, len(tail), bs):
            self._compress(tail[i:i + bs])
        self._buffer = b""

    def _compress(self, block: bytes) -> None:  # pragma: no cover - abstrato
        raise NotImplementedError

    # --------------------------------------------- utilitário para ataques
    @classmethod
    def state_from_digest(cls, digest: bytes) -> list:
        """Converte um digest de volta nas palavras do estado interno."""
        wb = cls.word_bytes
        return [int.from_bytes(digest[i:i + wb], cls.byteorder) for i in range(0, len(digest), wb)]
