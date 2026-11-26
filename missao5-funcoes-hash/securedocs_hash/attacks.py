"""
Ataques e testes sobre funções hash (item 6 da missão: "atacar/testar").

  1. avalanche()            – mede o efeito avalanche (1 bit muda ~50% da saída)
  2. birthday_attack()      – paradoxo do aniversário: colisão em ~2^(n/2) tentativas
  3. preimage_bruteforce()  – custo de 2^n para achar uma pré-imagem
  4. length_extension()     – ataque de extensão de comprimento (MD5, SHA-1, SHA-2)
  5. build_colliding_files()– "documento envenenado": dois arquivos com o MESMO hash
                              e conteúdos visíveis diferentes, usando colisões reais
                              de MD5 (geradas com fastcoll) e SHA-1 (SHAttered, 2017)
"""

from __future__ import annotations

import os
import random
import time
from pathlib import Path

from ._base import MerkleDamgard

DATA_DIR = Path(__file__).parent / "dados"


def _new(name, data=b""):
    from . import new
    return new(name, data)


def _digest(name, data, out_len=32):
    h = _new(name, data)
    return h.digest(out_len) if name.startswith("shake") else h.digest()


def _bits(b: bytes) -> int:
    return sum(bin(x).count("1") for x in b)


# ---------------------------------------------------------------------------
# 1. Efeito avalanche
# ---------------------------------------------------------------------------
def flip_bit(data: bytes, bit_index: int) -> bytes:
    b = bytearray(data)
    b[bit_index // 8] ^= 1 << (bit_index % 8)
    return bytes(b)


def avalanche(algorithm: str = "sha256", trials: int = 200, msg_len: int = 64, seed: int = 2026) -> dict:
    """
    Para ``trials`` mensagens aleatórias, inverte 1 bit aleatório e conta
    quantos bits do hash mudaram. O ideal (critério estrito de avalanche) é 50%.
    """
    rng = random.Random(seed)
    diffs = []
    for _ in range(trials):
        m = bytes(rng.getrandbits(8) for _ in range(msg_len))
        m2 = flip_bit(m, rng.randrange(msg_len * 8))
        a, b = _digest(algorithm, m), _digest(algorithm, m2)
        diffs.append(_bits(bytes(x ^ y for x, y in zip(a, b))))
    n_bits = len(_digest(algorithm, b"")) * 8
    mean = sum(diffs) / len(diffs)
    var = sum((d - mean) ** 2 for d in diffs) / len(diffs)
    return {
        "algoritmo": algorithm, "bits_saida": n_bits, "tentativas": trials,
        "media_bits": round(mean, 2), "media_pct": round(100 * mean / n_bits, 2),
        "desvio": round(var ** 0.5, 2), "min": min(diffs), "max": max(diffs),
        "amostras": diffs,
    }


# ---------------------------------------------------------------------------
# 2. Ataque do aniversário em hash truncado
# ---------------------------------------------------------------------------
def birthday_attack(algorithm: str = "sha256", bits: int = 32, seed: int | None = None) -> dict:
    """
    Procura duas mensagens diferentes cujo hash, TRUNCADO para ``bits`` bits,
    seja igual. Pelo paradoxo do aniversário, espera-se ~ sqrt(pi/2 * 2^bits)
    tentativas. Mostra por que um hash de n bits oferece só n/2 bits de
    segurança contra colisões – e por que 128 bits (MD5) é pouco.
    """
    rng = random.Random(seed)
    seen: dict[int, bytes] = {}
    mask_bytes = (bits + 7) // 8
    shift = mask_bytes * 8 - bits
    t0 = time.perf_counter()
    tries = 0
    while True:
        tries += 1
        m = f"Contrato SecureDocs - versao {rng.getrandbits(64):016x}".encode()
        tag = int.from_bytes(_digest(algorithm, m)[:mask_bytes], "big") >> shift
        if tag in seen and seen[tag] != m:
            return {
                "algoritmo": algorithm, "bits": bits, "tentativas": tries,
                "esperado": round((3.141592653589793 / 2 * 2 ** bits) ** 0.5),
                "msg1": seen[tag].decode(), "msg2": m.decode(),
                "hash_truncado": f"{tag:0{(bits + 3) // 4}x}",
                "tempo_s": round(time.perf_counter() - t0, 3),
            }
        seen[tag] = m


def preimage_bruteforce(target_prefix_hex: str, algorithm: str = "sha256", max_tries: int = 10 ** 7) -> dict:
    """
    Busca uma mensagem cujo hash comece com ``target_prefix_hex``.
    Custo esperado: 16^(len(prefixo)) tentativas – cresce exponencialmente.
    """
    t0 = time.perf_counter()
    for i in range(1, max_tries + 1):
        m = f"tentativa-{i}".encode()
        if _new(algorithm, m).hexdigest().startswith(target_prefix_hex):
            return {"encontrado": True, "mensagem": m.decode(), "tentativas": i,
                    "esperado": 16 ** len(target_prefix_hex), "tempo_s": round(time.perf_counter() - t0, 3)}
    return {"encontrado": False, "tentativas": max_tries}


# ---------------------------------------------------------------------------
# 3. Ataque de extensão de comprimento (length-extension)
# ---------------------------------------------------------------------------
def length_extension(hash_cls: type[MerkleDamgard], known_digest: bytes, secret_len: int,
                     known_message: bytes, extension: bytes) -> tuple[bytes, bytes]:
    """
    Cenário: o servidor autentica mensagens com  tag = H(segredo || mensagem)
    (construção INSEGURA). O atacante conhece ``mensagem``, ``tag`` e o
    tamanho do segredo – mas NÃO o segredo.

    Como em Merkle–Damgård o digest É o estado interno, o atacante "retoma"
    o hash a partir dele e acrescenta dados, obtendo uma tag válida para

        segredo || mensagem || padding || extensão

    Retorna (mensagem_forjada_sem_segredo, tag_forjada).
    """
    orig_len = secret_len + len(known_message)
    glue = hash_cls.padding(orig_len)
    state = hash_cls.state_from_digest(known_digest)
    # Para SHA-224/384 o digest é truncado e o ataque não se aplica diretamente.
    if len(state) != len(hash_cls._IV):
        raise ValueError(f"{hash_cls.name}: saída truncada – estado interno incompleto")
    h = hash_cls(_state=state, _length=orig_len + len(glue))
    h.update(extension)
    return known_message + glue + extension, h.digest()


# ---------------------------------------------------------------------------
# 4. Documentos "envenenados" com colisão real
# ---------------------------------------------------------------------------
MAGIC = b"\n--SECUREDOCS-COLLISION-DEMO--\n"


def build_colliding_files(prefix1: bytes, prefix2: bytes, text_a: bytes, text_b: bytes) -> tuple[bytes, bytes]:
    """
    Recebe dois PREFIXOS DIFERENTES com o MESMO hash (colisão) e monta dois
    arquivos completos que continuam colidindo, mas exibem textos diferentes.

    Truque clássico (Daum & Lucks, 2005): como o estado interno após os
    prefixos é idêntico, qualquer SUFIXO comum preserva a colisão.
    O sufixo contém uma cópia do prefixo 1 e os dois textos; o "leitor"
    compara o início do arquivo com essa cópia para decidir o que mostrar.
    """
    assert len(prefix1) == len(prefix2) and prefix1 != prefix2
    suffix = MAGIC + len(prefix1).to_bytes(4, "big") + prefix1 + \
        len(text_a).to_bytes(4, "big") + text_a + len(text_b).to_bytes(4, "big") + text_b
    return prefix1 + suffix, prefix2 + suffix


def read_colliding_file(data: bytes) -> str:
    """'Visualizador' do documento: mostra o texto A ou B conforme o prefixo."""
    i = data.rindex(MAGIC)
    p = i + len(MAGIC)
    n = int.from_bytes(data[p:p + 4], "big"); p += 4
    ref = data[p:p + n]; p += n
    la = int.from_bytes(data[p:p + 4], "big"); p += 4
    ta = data[p:p + la]; p += la
    lb = int.from_bytes(data[p:p + 4], "big"); p += 4
    tb = data[p:p + lb]
    return (ta if data[:n] == ref else tb).decode("utf-8")


def load_sha1_collision() -> tuple[bytes, bytes]:
    """Prefixos de 320 bytes da colisão SHAttered (Stevens, Bursztein et al., 2017)."""
    return ((DATA_DIR / "shattered_prefixo1.bin").read_bytes(),
            (DATA_DIR / "shattered_prefixo2.bin").read_bytes())


def load_md5_collision() -> tuple[bytes, bytes]:
    """Par de colisão MD5 gerado com o fastcoll (M. Stevens) para este projeto."""
    return ((DATA_DIR / "md5_colisao1.bin").read_bytes(),
            (DATA_DIR / "md5_colisao2.bin").read_bytes())


def timing(algorithm: str, size: int = 100_000, repeat: int = 1) -> float:
    """Vazão aproximada (KB/s) da implementação em Python puro."""
    data = os.urandom(size)
    t0 = time.perf_counter()
    for _ in range(repeat):
        _new(algorithm, data).digest() if not algorithm.startswith("shake") else _new(algorithm, data).digest(32)
    dt = (time.perf_counter() - t0) / repeat
    return size / 1024 / dt
