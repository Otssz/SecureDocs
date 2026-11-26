"""
Interface de linha de comando do securedocs_hash.

Exemplos:
    python -m securedocs_hash hash contrato.pdf                    # SHA-256 (padrão)
    python -m securedocs_hash hash contrato.pdf -a todos            # todos os algoritmos
    python -m securedocs_hash comparar contrato.pdf recebido.pdf -a sha3_256
    python -m securedocs_hash verificar recebido.pdf <hash_esperado> -a sha256
    python -m securedocs_hash texto "Olá, SecureDocs" -a md5
    python -m securedocs_hash hmac contrato.pdf --chave segredo
    python -m securedocs_hash manifesto criar  pasta_docs --chave segredo
    python -m securedocs_hash manifesto verificar pasta_docs --chave segredo
    python -m securedocs_hash avalanche -a sha256 -n 500
    python -m securedocs_hash aniversario -a sha256 -b 32
    python -m securedocs_hash listar
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import ALGORITHMS, STATUS, new
from .attacks import avalanche, birthday_attack
from .hmac import HMAC
from .integrity import compare_files, create_manifest, hash_file, verify_file, verify_manifest

VERDE, VERMELHO, AMARELO, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[0m"


def _algs(arg: str) -> list[str]:
    return [a for a in ALGORITHMS if not a.startswith("shake")] if arg == "todos" else [arg]


def _hex(name: str, data: bytes) -> str:
    h = new(name, data)
    return h.hexdigest(32) if name.startswith("shake") else h.hexdigest()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="securedocs_hash", description="Funções hash do SecureDocs (Missão 5)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("hash", help="calcula o hash de um arquivo")
    s.add_argument("arquivo"); s.add_argument("-a", "--algoritmo", default="sha256")

    s = sub.add_parser("texto", help="calcula o hash de um texto (UTF-8)")
    s.add_argument("texto"); s.add_argument("-a", "--algoritmo", default="sha256")

    s = sub.add_parser("comparar", help="compara dois arquivos pelo hash")
    s.add_argument("a"); s.add_argument("b"); s.add_argument("-a", "--algoritmo", default="sha256")

    s = sub.add_parser("verificar", help="verifica um arquivo contra um hash esperado")
    s.add_argument("arquivo"); s.add_argument("esperado"); s.add_argument("-a", "--algoritmo", default="sha256")

    s = sub.add_parser("hmac", help="calcula o HMAC de um arquivo")
    s.add_argument("arquivo"); s.add_argument("--chave", required=True); s.add_argument("-a", "--algoritmo", default="sha256")

    s = sub.add_parser("manifesto", help="cria/verifica manifesto de integridade de uma pasta")
    s.add_argument("acao", choices=["criar", "verificar"]); s.add_argument("pasta")
    s.add_argument("--chave", required=True); s.add_argument("-a", "--algoritmo", default="sha3_256")

    s = sub.add_parser("avalanche", help="mede o efeito avalanche")
    s.add_argument("-a", "--algoritmo", default="sha256"); s.add_argument("-n", type=int, default=200)

    s = sub.add_parser("aniversario", help="ataque do aniversário em hash truncado")
    s.add_argument("-a", "--algoritmo", default="sha256"); s.add_argument("-b", "--bits", type=int, default=24)

    sub.add_parser("listar", help="lista os algoritmos e sua situação de segurança")

    a = p.parse_args(argv)

    if a.cmd == "hash":
        for alg in _algs(a.algoritmo):
            print(f"{alg:<11} {hash_file(a.arquivo, alg) if not alg.startswith('shake') else _hex(alg, Path(a.arquivo).read_bytes())}  {a.arquivo}")
    elif a.cmd == "texto":
        for alg in _algs(a.algoritmo):
            print(f"{alg:<11} {_hex(alg, a.texto.encode('utf-8'))}")
    elif a.cmd == "comparar":
        r = compare_files(a.a, a.b, a.algoritmo)
        print(f"{a.a}: {r['hash_a']}\n{a.b}: {r['hash_b']}")
        if r["iguais"]:
            print(f"{VERDE}IDÊNTICOS – o documento não foi alterado.{RESET}")
        else:
            print(f"{VERMELHO}DIFERENTES – o documento FOI ALTERADO.{RESET} "
                  f"{r['bits_diferentes']}/{r['total_bits']} bits diferentes ({r['percentual']}%)")
        return 0 if r["iguais"] else 1
    elif a.cmd == "verificar":
        ok = verify_file(a.arquivo, a.esperado, a.algoritmo)
        print(f"{VERDE}ÍNTEGRO{RESET}" if ok else f"{VERMELHO}ALTERADO – hash não confere{RESET}")
        return 0 if ok else 1
    elif a.cmd == "hmac":
        h = HMAC(a.chave.encode(), Path(a.arquivo).read_bytes(), a.algoritmo)
        print(f"{h.name}: {h.hexdigest()}")
    elif a.cmd == "manifesto":
        out = Path(a.pasta) / "manifesto.json"
        if a.acao == "criar":
            m = create_manifest(a.pasta, a.chave.encode(), a.algoritmo, str(out))
            print(f"Manifesto com {len(m['arquivos'])} arquivo(s) salvo em {out}")
        else:
            r = verify_manifest(a.pasta, str(out), a.chave.encode())
            print(json.dumps(r, indent=2, ensure_ascii=False))
            return 0 if r["manifesto_autentico"] and not (r["alterados"] or r["ausentes"]) else 1
    elif a.cmd == "avalanche":
        r = avalanche(a.algoritmo, a.n)
        r.pop("amostras")
        print(json.dumps(r, indent=2, ensure_ascii=False))
    elif a.cmd == "aniversario":
        print(json.dumps(birthday_attack(a.algoritmo, a.bits), indent=2, ensure_ascii=False))
    elif a.cmd == "listar":
        for alg in ALGORITHMS:
            cor = VERMELHO if "QUEBRADO" in STATUS[alg] else VERDE
            print(f"{alg:<11} {cor}{STATUS[alg]}{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
