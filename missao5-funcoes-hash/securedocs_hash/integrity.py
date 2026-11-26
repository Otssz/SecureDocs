"""
Ferramentas de integridade de documentos para o SecureDocs.

Responde à pergunta da Missão 5:
    "Como verificar se um documento recebido é exatamente igual ao documento enviado?"

Fluxo proposto:
  1. O remetente calcula H(documento) e o envia/publica por um canal confiável
     (ou protege o valor com HMAC/assinatura digital).
  2. O destinatário recalcula H(documento recebido).
  3. Se os dois valores forem idênticos (comparação em tempo constante), o
     documento é íntegro; qualquer diferença, por menor que seja, indica alteração.

Também fornece o "manifesto de integridade": um arquivo JSON com o hash de
cada documento armazenado, autenticado por HMAC, para detectar adulterações
no repositório do SecureDocs (documentos em repouso).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .hmac import HMAC, compare_digest

CHUNK = 64 * 1024  # leitura em blocos: permite processar arquivos grandes


def _new(algorithm: str, data: bytes = b""):
    from . import new
    return new(algorithm, data)


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    return _new(algorithm, data).hexdigest()


def hash_file(path, algorithm: str = "sha256") -> str:
    """Calcula o hash de um arquivo lendo-o em blocos (streaming)."""
    h = _new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_file(path, expected_hex: str, algorithm: str = "sha256") -> bool:
    """Retorna True se o hash do arquivo for igual ao valor esperado."""
    return compare_digest(hash_file(path, algorithm), expected_hex.strip().lower())


def bit_difference(hex_a: str, hex_b: str) -> int:
    """Quantidade de bits diferentes entre dois digests (distância de Hamming)."""
    a, b = bytes.fromhex(hex_a), bytes.fromhex(hex_b)
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def compare_files(path_a, path_b, algorithm: str = "sha256") -> dict:
    """Compara dois arquivos pelo hash e mede o efeito avalanche."""
    ha, hb = hash_file(path_a, algorithm), hash_file(path_b, algorithm)
    total_bits = len(ha) * 4
    diff = bit_difference(ha, hb)
    return {
        "algoritmo": algorithm,
        "hash_a": ha,
        "hash_b": hb,
        "iguais": compare_digest(ha, hb),
        "bits_diferentes": diff,
        "total_bits": total_bits,
        "percentual": round(100 * diff / total_bits, 2),
    }


# ---------------------------------------------------------------------------
# Manifesto de integridade autenticado (documentos em repouso)
# ---------------------------------------------------------------------------
def _canonical(entries: dict) -> bytes:
    return json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()


def create_manifest(directory, key: bytes, algorithm: str = "sha3_256",
                    output: str | None = None) -> dict:
    """
    Gera um manifesto com o hash de cada arquivo da pasta e um HMAC-SHA-256
    sobre o conjunto. Sem a chave, um invasor não consegue alterar um
    documento E atualizar o manifesto sem ser detectado.
    """
    directory = Path(directory)
    files = {}
    for p in sorted(directory.rglob("*")):
        if p.is_file() and p.name != "manifesto.json":
            files[str(p.relative_to(directory)).replace(os.sep, "/")] = hash_file(p, algorithm)
    body = {"algoritmo": algorithm, "gerado_em": time.strftime("%Y-%m-%dT%H:%M:%S"), "arquivos": files}
    body["hmac_sha256"] = HMAC(key, _canonical(body)).hexdigest()
    if output:
        Path(output).write_text(json.dumps(body, indent=2, ensure_ascii=False), encoding="utf-8")
    return body


def verify_manifest(directory, manifest, key: bytes) -> dict:
    """
    Verifica (1) a autenticidade do manifesto (HMAC) e (2) a integridade de
    cada arquivo. Retorna um relatório com arquivos íntegros, alterados,
    ausentes e novos.
    """
    if isinstance(manifest, (str, Path)):
        manifest = json.loads(Path(manifest).read_text(encoding="utf-8"))
    body = {k: v for k, v in manifest.items() if k != "hmac_sha256"}
    manifest_ok = compare_digest(HMAC(key, _canonical(body)).hexdigest(), manifest.get("hmac_sha256", ""))

    directory = Path(directory)
    alg = manifest["algoritmo"]
    report = {"manifesto_autentico": manifest_ok, "integros": [], "alterados": [], "ausentes": [], "novos": []}
    seen = set()
    for name, expected in manifest["arquivos"].items():
        p = directory / name
        seen.add(name)
        if not p.exists():
            report["ausentes"].append(name)
        elif verify_file(p, expected, alg):
            report["integros"].append(name)
        else:
            report["alterados"].append(name)
    for p in sorted(directory.rglob("*")):
        rel = str(p.relative_to(directory)).replace(os.sep, "/")
        if p.is_file() and p.name != "manifesto.json" and rel not in seen:
            report["novos"].append(rel)
    return report
