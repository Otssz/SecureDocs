import os

from simetricas import *

h = bytes.fromhex


def conferir(nome, obtido, esperado):
    status = "OK  " if obtido == esperado else "FALHOU"
    print(f"  [{status}] {nome}")

    if obtido != esperado:
        raise SystemExit(1)


print("=== DES (vetor classico) ===")
chaves = expandir_chave_des(h("133457799BBCDFF1"))
cifrado = cifrar_bloco_des(h("0123456789ABCDEF"), chaves)
conferir("cifrar", cifrado.hex().upper(), "85E813540F0AB405")
conferir("decifrar", decifrar_bloco_des(cifrado, chaves), h("0123456789ABCDEF"))


print("\n=== AES (FIPS-197, apendice C) ===")
claro = h("00112233445566778899aabbccddeeff")
vetores = {
    128: ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    192: ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    256: ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
}

for bits, (chave, esperado) in vetores.items():
    chaves = expandir_chave_aes(h(chave))
    cifrado = cifrar_bloco_aes(claro, chaves)
    conferir(f"AES-{bits} cifrar", cifrado.hex(), esperado)
    conferir(f"AES-{bits} decifrar", decifrar_bloco_aes(cifrado, chaves), claro)


print("\n=== RC5-32/12/16 (vetores do artigo de Rivest) ===")
for chave, claro_hex, esperado in [
    ("00" * 16, "00" * 8, "21A5DBEE154B8F6D"),
    ("915F4619BE41B2516355A50110A9CE91", "21A5DBEE154B8F6D", "F7C013AC5B2B8952"),
]:
    S = expandir_chave_rc5(h(chave))
    cifrado = cifrar_bloco_rc5(h(claro_hex), S)
    conferir(f"RC5 cifrar {claro_hex}", cifrado.hex().upper(), esperado)
    conferir(f"RC5 decifrar {esperado}", decifrar_bloco_rc5(cifrado, S), h(claro_hex))


print("\n=== Modo CBC + padding (todos os algoritmos, varios tamanhos) ===")
for nome, (_, _, _, _, tam_chave) in ALGORITMOS.items():
    chave = gerar_chave(tam_chave)

    for n in (0, 1, 7, 8, 15, 16, 17, 100):
        dados = os.urandom(n)
        conferir(f"{nome} CBC com {n} bytes", decifrar_cbc(cifrar_cbc(dados, chave, nome), chave, nome), dados)


print("\n=== Chave errada nao revela o conteudo ===")
chave = gerar_chave(16)
cifrado = cifrar_cbc(b"contrato confidencial", chave, "AES")

try:
    resultado = decifrar_cbc(cifrado, gerar_chave(16), "AES")
    conferir("chave errada", resultado == b"contrato confidencial", False)
except ValueError:
    conferir("chave errada rejeitada (padding invalido)", True, True)

print("\nTudo certo.")
