"""
HMAC – Keyed-Hash Message Authentication Code (RFC 2104 / FIPS 198-1).

Um hash sozinho garante INTEGRIDADE apenas se o valor de referência chegar por
um canal confiável: um atacante que altera o contrato.pdf no caminho pode
simplesmente recalcular o SHA-256 e substituir também o hash publicado.

O HMAC acrescenta uma CHAVE SECRETA compartilhada:

    HMAC(K, m) = H( (K' ⊕ opad) || H( (K' ⊕ ipad) || m ) )

    K'   = chave ajustada ao tamanho do bloco (hash da chave se for maior)
    ipad = 0x36 repetido;  opad = 0x5c repetido

Assim obtemos INTEGRIDADE + AUTENTICAÇÃO DA ORIGEM (somente quem conhece a
chave gera um HMAC válido). O HMAC NÃO oferece não-repúdio (as duas partes
conhecem a chave) – isso exigirá assinaturas digitais (missões futuras).

A construção aninhada também neutraliza o ataque de extensão de comprimento.
"""

from __future__ import annotations


class HMAC:
    def __init__(self, key: bytes, msg: bytes = b"", digestmod=None):
        if digestmod is None:
            from .sha2 import SHA256
            digestmod = SHA256
        if isinstance(digestmod, str):
            from . import new as _new
            name = digestmod
            digestmod = lambda data=b"": _new(name, data)  # noqa: E731
        self._factory = digestmod
        probe = digestmod()
        bs = probe.block_size
        self.digest_size = probe.digest_size
        self.block_size = bs
        self.name = f"hmac-{probe.name}"

        key = bytes(key)
        if len(key) > bs:                       # chave longa -> hash da chave
            key = digestmod(key).digest()
        key = key.ljust(bs, b"\x00")            # completa com zeros

        self._inner = digestmod(bytes(k ^ 0x36 for k in key))
        self._outer = digestmod(bytes(k ^ 0x5C for k in key))
        if msg:
            self.update(msg)

    def update(self, msg: bytes) -> "HMAC":
        self._inner.update(msg)
        return self

    def digest(self) -> bytes:
        outer = self._outer.copy()
        outer.update(self._inner.digest())
        return outer.digest()

    def hexdigest(self) -> str:
        return self.digest().hex()


def hmac_digest(key: bytes, msg: bytes, digestmod="sha256") -> bytes:
    return HMAC(key, msg, digestmod).digest()


def compare_digest(a: bytes | str, b: bytes | str) -> bool:
    """
    Comparação em TEMPO CONSTANTE. Comparar hashes com ``==`` pode vazar, pelo
    tempo de resposta, quantos bytes iniciais coincidem (ataque de temporização).
    """
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
