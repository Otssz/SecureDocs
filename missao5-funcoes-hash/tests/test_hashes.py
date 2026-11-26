"""
Testes da biblioteca securedocs_hash.

Executar:   python -m pytest -v      (ou)   python tests/test_hashes.py

Valida as implementações de três formas:
  1. Vetores de teste oficiais (RFC 1321, FIPS 180-4, FIPS 202, RFC 4231);
  2. Comparação com o módulo hashlib (OpenSSL) em milhares de entradas aleatórias,
     incluindo os tamanhos críticos ao redor das fronteiras de bloco/padding;
  3. Propriedades e ataques (avalanche, extensão de comprimento, colisões reais).
"""

import hashlib
import hmac as std_hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import securedocs_hash as sh  # noqa: E402
from securedocs_hash import attacks  # noqa: E402

# ---------------------------------------------------------------- vetores oficiais
VECTORS = {
    # RFC 1321, apêndice A.5
    ("md5", b""): "d41d8cd98f00b204e9800998ecf8427e",
    ("md5", b"abc"): "900150983cd24fb0d6963f7d28e17f72",
    ("md5", b"message digest"): "f96b697d7cb7938d525a2f31aaf161d0",
    # FIPS 180-4 (exemplos do NIST)
    ("sha1", b"abc"): "a9993e364706816aba3e25717850c26c9cd0d89d",
    ("sha224", b"abc"): "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    ("sha256", b"abc"): "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ("sha256", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"):
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ("sha384", b"abc"): "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                        "8086072ba1e7cc2358baeca134c825a7",
    ("sha512", b"abc"): "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    # FIPS 202
    ("sha3_256", b""): "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    ("sha3_256", b"abc"): "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ("sha3_512", b"abc"): "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                          "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
}


def test_official_vectors():
    for (alg, msg), expected in VECTORS.items():
        assert sh.new(alg, msg).hexdigest() == expected, alg


def test_million_a_sha256():
    """Vetor longo do FIPS 180-4: 1 milhão de letras 'a' (processado em pedaços)."""
    h = sh.sha256()
    for _ in range(1000):
        h.update(b"a" * 1000)
    assert h.hexdigest() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


def test_against_hashlib_random_and_boundaries():
    rng = random.Random(42)
    sizes = list(range(0, 260)) + [rng.randrange(260, 3000) for _ in range(30)]
    for alg in sh.ALGORITHMS:
        for n in sizes:
            data = os.urandom(n)
            if alg.startswith("shake"):
                assert sh.new(alg, data).digest(100) == hashlib.new(alg, data).digest(100), (alg, n)
            else:
                assert sh.new(alg, data).digest() == hashlib.new(alg, data).digest(), (alg, n)


def test_streaming_equals_one_shot():
    data = os.urandom(5000)
    for alg in sh.ALGORITHMS:
        if alg.startswith("shake"):
            continue
        h = sh.new(alg)
        i = 0
        while i < len(data):
            step = random.randint(1, 300)
            h.update(data[i:i + step])
            i += step
        assert h.hexdigest() == sh.new(alg, data).hexdigest()


def test_digest_does_not_change_state():
    h = sh.sha256(b"parte 1 ")
    _ = h.digest()
    h.update(b"parte 2")
    assert h.hexdigest() == hashlib.sha256(b"parte 1 parte 2").hexdigest()


def test_derived_constants():
    from securedocs_hash.sha2 import K256, K512, IV256
    assert K256[0] == 0x428A2F98 and K256[63] == 0xC67178F2
    assert K512[0] == 0x428A2F98D728AE22 and K512[79] == 0x6C44198C4A475817
    assert IV256[0] == 0x6A09E667
    from securedocs_hash.sha3 import RC
    assert RC[0] == 1 and RC[23] == 0x8000000080008008


def test_hmac_rfc4231():
    # RFC 4231, caso de teste 2
    key, msg = b"Jefe", b"what do ya want for nothing?"
    assert sh.HMAC(key, msg).hexdigest() == \
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    for alg in ["md5", "sha1", "sha512", "sha3_256"]:
        k = os.urandom(200)
        assert sh.HMAC(k, b"x" * 77, alg).digest() == std_hmac.new(k, b"x" * 77, alg).digest()


def test_compare_digest():
    assert sh.compare_digest("abc", "abc")
    assert not sh.compare_digest("abc", "abd")
    assert not sh.compare_digest("abc", "ab")


def test_avalanche_near_50_percent():
    for alg in ["md5", "sha1", "sha256", "sha3_256"]:
        r = attacks.avalanche(alg, trials=150)
        assert 45 <= r["media_pct"] <= 55, r


def test_length_extension_works_on_merkle_damgard():
    secret = b"chave-secreta-do-servidor"
    msg = b"usuario=cliente&doc=contrato.pdf"
    ext = b"&papel=admin"
    for cls in [sh.MD5, sh.SHA1, sh.SHA256, sh.SHA512]:
        tag = cls(secret + msg).digest()
        forged_msg, forged_tag = attacks.length_extension(cls, tag, len(secret), msg, ext)
        # O servidor, que conhece o segredo, aceita a mensagem forjada:
        assert cls(secret + forged_msg).digest() == forged_tag
        assert forged_msg.endswith(ext)


def test_length_extension_fails_on_hmac():
    secret, msg, ext = b"k" * 16, b"doc=contrato", b"&admin=1"
    tag = sh.HMAC(secret, msg).digest()
    forged_msg, forged_tag = attacks.length_extension(sh.SHA256, tag, len(secret) + 64, msg, ext)
    assert sh.HMAC(secret, forged_msg).digest() != forged_tag


def test_real_md5_collision():
    a, b = attacks.load_md5_collision()
    assert a != b
    assert sh.md5(a).digest() == sh.md5(b).digest()
    assert sh.sha256(a).digest() != sh.sha256(b).digest()


def test_real_sha1_collision_shattered():
    a, b = attacks.load_sha1_collision()
    assert a != b
    assert sh.sha1(a).hexdigest() == "f92d74e3874587aaf443d1db961d4e26dde13e9c"
    assert sh.sha1(a).digest() == sh.sha1(b).digest()
    assert sh.sha256(a).digest() != sh.sha256(b).digest()
    assert sh.sha3_256(a).digest() != sh.sha3_256(b).digest()


def test_poisoned_documents():
    a, b = attacks.load_md5_collision()
    fa, fb = attacks.build_colliding_files(a, b, "Valor: R$ 10.000".encode(), "Valor: R$ 100.000".encode())
    assert sh.md5(fa).digest() == sh.md5(fb).digest()
    assert attacks.read_colliding_file(fa) != attacks.read_colliding_file(fb)


def test_birthday_small():
    r = attacks.birthday_attack("sha256", 16, seed=1)
    assert r["msg1"] != r["msg2"]


def test_manifest(tmp_path=None):
    import tempfile
    d = Path(tmp_path or tempfile.mkdtemp())
    (d / "a.txt").write_text("contrato A")
    (d / "b.txt").write_text("contrato B")
    key = b"chave"
    m = sh.create_manifest(d, key)
    assert sh.verify_manifest(d, m, key)["integros"] == ["a.txt", "b.txt"]
    (d / "b.txt").write_text("contrato B adulterado")
    r = sh.verify_manifest(d, m, key)
    assert r["alterados"] == ["b.txt"] and r["manifesto_autentico"]
    m["arquivos"]["b.txt"] = sh.hash_file(d / "b.txt", "sha3_256")   # invasor "conserta" o manifesto
    assert not sh.verify_manifest(d, m, key)["manifesto_autentico"]   # mas o HMAC denuncia


if __name__ == "__main__":
    fns = [v for k, v in dict(globals()).items() if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"OK  {fn.__name__}")
    print(f"\n{len(fns)} testes passaram.")
