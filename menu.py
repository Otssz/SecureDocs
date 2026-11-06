from simetricas import *

MENU = """
============================================================
  SecureDocs - Missão 3: Criptografia Simétrica
============================================================
    1 - DES
    2 - RC5
    3 - AES
    4 - Comparar DES x RC5 x AES

    0 - Sair
"""


def titulo(texto):
    print("\n" + "=" * 60)
    print("  " + texto)
    print("=" * 60)


def perguntar(pergunta, padrao):
    resposta = input(f"{pergunta} [Enter = {padrao}]: ").strip()

    if resposta == "":
        return str(padrao)

    return resposta


def pedir_chave(nome, tamanho_padrao):
    resposta = perguntar(f"Chave em hexadecimal ({tamanho_padrao} bytes)", "sorteada")

    if resposta == "sorteada":
        return gerar_chave(tamanho_padrao)

    try:
        return bytes.fromhex(resposta)
    except ValueError:
        raise ValueError("a chave precisa estar em hexadecimal (ex.: 00112233...)")


def bloco_simetrico(nome, expandir, cifrar_bloco, decifrar_bloco, tamanho_bloco, tamanho_chave, formula):
    titulo(f"{nome}  |  {formula}")
    chave = pedir_chave(nome, tamanho_chave)
    texto = perguntar(f"Bloco de {tamanho_bloco} caracteres", "A" * tamanho_bloco)
    bloco = texto.encode("utf-8")

    if len(bloco) != tamanho_bloco:
        raise ValueError(f"o bloco de {nome} precisa ter exatamente {tamanho_bloco} bytes")

    chaves = expandir(chave)
    cifrado = cifrar_bloco(bloco, chaves)

    print()
    print("  Chave       :", chave.hex())
    print("  Claro (hex) :", bloco.hex())
    print("  Cifrado     :", cifrado.hex())
    print("  Decifrado   :", decifrar_bloco(cifrado, chaves).hex())


def des():
    bloco_simetrico("DES", expandir_chave_des, cifrar_bloco_des, decifrar_bloco_des, 8, 8,
                    "Feistel, 16 rodadas, bloco 64 bits, chave 56 bits")


def rc5():
    bloco_simetrico("RC5-32/12/16", expandir_chave_rc5, cifrar_bloco_rc5, decifrar_bloco_rc5, 8, 16,
                    "A = ((A xor B) <<< B) + S[2i]")


def aes():
    bloco_simetrico("AES-128", expandir_chave_aes, cifrar_bloco_aes, decifrar_bloco_aes, 16, 16,
                    "SubBytes, ShiftRows, MixColumns, AddRoundKey")


def comparar():
    titulo("Comparação: DES x RC5 x AES")
    print()
    print(f"  {'':14}{'DES':>14}{'RC5-32/12/16':>16}{'AES-128':>14}")
    print(f"  {'Bloco':14}{'64 bits':>14}{'64 bits':>16}{'128 bits':>14}")
    print(f"  {'Chave':14}{'56 bits':>14}{'0-2040 bits':>16}{'128/192/256':>14}")
    print(f"  {'Rodadas':14}{'16':>14}{'0-255 (12)':>16}{'10/12/14':>14}")
    print(f"  {'Estrutura':14}{'Feistel':>14}{'Feistel-like':>16}{'SP-network':>14}")
    print(f"  {'Situação':14}{'quebrado':>14}{'sem ataque':>16}{'padrão atual':>14}")
    print()
    print("  Espaço de chaves: DES = 2^56 | AES-128 = 2^128")
    print("  A 10^12 chaves/s, DES cai em ~20 h; AES-128 levaria ~10^19 anos.")


OPCOES = {
    "1": des,
    "2": rc5,
    "3": aes,
    "4": comparar,
}


def main():
    while True:
        print(MENU)
        escolha = input("Escolha uma opção: ").strip()

        if escolha == "0":
            break

        if escolha not in OPCOES:
            print("Opção inválida.")
            continue

        try:
            OPCOES[escolha]()
        except ValueError as erro:
            print("\n  ERRO:", erro)

        input("\nPressione Enter para voltar ao menu...")


if __name__ == "__main__":
    main()
