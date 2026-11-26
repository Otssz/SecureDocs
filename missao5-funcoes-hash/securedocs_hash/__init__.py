"""
securedocs_hash – Biblioteca didática de funções hash criptográficas em Python puro.

Projeto SecureDocs (TechSecure) – Missão 5: "O documento foi alterado".

Algoritmos implementados do zero (sem usar hashlib no cálculo):
    MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256,
    SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 e HMAC.

Uso rápido:
    >>> import securedocs_hash as sh
    >>> sh.sha256(b"abc").hexdigest()
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    >>> sh.new("sha3_256", b"abc").hexdigest()[:16]
    '3a985da74fe225b2'
    >>> sh.hash_file("contrato.pdf", "sha256")          # doctest: +SKIP
"""

from .md5 import MD5, md5
from .sha1 import SHA1, sha1
from .sha2 import (SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256,
                   sha224, sha256, sha384, sha512, sha512_224, sha512_256)
from .sha3 import (SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256,
                   sha3_224, sha3_256, sha3_384, sha3_512, shake_128, shake_256)
from .hmac import HMAC, hmac_digest, compare_digest
from .integrity import (hash_bytes, hash_file, verify_file, compare_files,
                        create_manifest, verify_manifest, bit_difference)

__version__ = "1.0.0"

ALGORITHMS = {
    "md5": MD5,
    "sha1": SHA1,
    "sha224": SHA224,
    "sha256": SHA256,
    "sha384": SHA384,
    "sha512": SHA512,
    "sha512_224": SHA512_224,
    "sha512_256": SHA512_256,
    "sha3_224": SHA3_224,
    "sha3_256": SHA3_256,
    "sha3_384": SHA3_384,
    "sha3_512": SHA3_512,
    "shake_128": SHAKE128,
    "shake_256": SHAKE256,
}

# Classificação de segurança (situação em 2026)
STATUS = {
    "md5": "QUEBRADO – colisões em segundos (Wang 2004; prefixo escolhido, Stevens 2007)",
    "sha1": "QUEBRADO – colisão prática SHAttered (2017) e prefixo escolhido (2020)",
    "sha224": "Seguro – 112 bits contra colisão",
    "sha256": "Seguro – 128 bits contra colisão (recomendado)",
    "sha384": "Seguro – 192 bits contra colisão",
    "sha512": "Seguro – 256 bits contra colisão",
    "sha512_224": "Seguro – 112 bits contra colisão",
    "sha512_256": "Seguro – 128 bits contra colisão",
    "sha3_224": "Seguro – 112 bits contra colisão",
    "sha3_256": "Seguro – 128 bits contra colisão (recomendado)",
    "sha3_384": "Seguro – 192 bits contra colisão",
    "sha3_512": "Seguro – 256 bits contra colisão",
    "shake_128": "Seguro – até 128 bits (XOF)",
    "shake_256": "Seguro – até 256 bits (XOF)",
}


def new(name: str, data: bytes = b""):
    """Cria um objeto hash pelo nome (mesma ideia de ``hashlib.new``)."""
    key = name.lower().replace("-", "_").replace("/", "_")
    aliases = {"sha3256": "sha3_256", "sha_256": "sha256", "sha_1": "sha1"}
    key = aliases.get(key, key)
    if key not in ALGORITHMS:
        raise ValueError(f"Algoritmo desconhecido: {name}. Disponíveis: {', '.join(ALGORITHMS)}")
    return ALGORITHMS[key](data)


algorithms_available = tuple(ALGORITHMS)

__all__ = [
    "new", "algorithms_available", "ALGORITHMS", "STATUS",
    "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512", "shake_128", "shake_256",
    "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA512_224", "SHA512_256",
    "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512", "SHAKE128", "SHAKE256",
    "HMAC", "hmac_digest", "compare_digest",
    "hash_bytes", "hash_file", "verify_file", "compare_files",
    "create_manifest", "verify_manifest", "bit_difference",
]
