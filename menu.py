import os

from criptografias import *
from simetricas import *

MENSAGEM = "TRANSFERIR DOCUMENTO PARA SERVIDOR CENTRAL"

MENU = """
============================================================
  SecureDocs - Missões 2 e 3
============================================================
  CIFRAS CLÁSSICAS
    1 - César
    2 - Substituição
    3 - Afim
    4 - Vigenère
    5 - Hill
    6 - Transposição
    7 - Fluxo
    8 - A mensagem em todas as cifras

  CRIPTOGRAFIA SIMÉTRICA (Missão 3)
    9 - DES
   10 - RC5
   11 - AES
   12 - Comparar DES x RC5 x AES
   13 - Experimento: cifrar um arquivo com AES

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


def perguntar_numero(pergunta, padrao):
    resposta = perguntar(pergunta, padrao)

    if not resposta.lstrip("-").isdigit():
        raise ValueError(f"'{resposta}' nao e um numero inteiro")

    return int(resposta)


def mostrar(texto, chave, cifrado, decifrado):
    print()
    print("  Texto claro :", preparar_texto(texto))
    print("  Chave       :", chave)
    print("  Cifrado     :", cifrado)
    print("  Decifrado   :", decifrado)


def cesar():
    titulo("Cifra de César  |  C = (P + k) mod 26")
    texto = perguntar("Texto", MENSAGEM)
    k = perguntar_numero("Chave", 3)

    cifrado = cifrar_cesar(texto, k)
    mostrar(texto, k, cifrado, decifrar_cesar(cifrado, k))


def substituicao():
    titulo("Cifra de Substituição  |  cada letra vira outra letra fixa")
    texto = perguntar("Texto", MENSAGEM)
    chave = perguntar("Chave (26 letras)", "QWERTYUIOPASDFGHJKLZXCVBNM")

    cifrado = cifrar_substituicao(texto, chave)
    mostrar(texto, chave, cifrado, decifrar_substituicao(cifrado, chave))
    print("\n  Alfabeto    :", ALFABETO)
    print("  vira        :", preparar_texto(chave))


def afim():
    titulo("Cifra Afim  |  C = (a * P + b) mod 26")
    texto = perguntar("Texto", MENSAGEM)
    a = perguntar_numero("Chave a", 5)
    b = perguntar_numero("Chave b", 8)

    cifrado = cifrar_afim(texto, a, b)
    mostrar(texto, f"a={a}, b={b}", cifrado, decifrar_afim(cifrado, a, b))


def vigenere():
    titulo("Cifra de Vigenère  |  C[i] = (P[i] + K[i]) mod 26")
    texto = perguntar("Texto", MENSAGEM)
    chave = perguntar("Chave", "SEGREDO")

    cifrado = cifrar_vigenere(texto, chave)
    mostrar(texto, chave, cifrado, decifrar_vigenere(cifrado, chave))


def hill():
    titulo("Cifra de Hill  |  C = K * P mod 26,  K = [[a, b], [c, d]]")
    texto = perguntar("Texto", MENSAGEM)
    a = perguntar_numero("a", 3)
    b = perguntar_numero("b", 3)
    c = perguntar_numero("c", 2)
    d = perguntar_numero("d", 5)
    matriz = [[a, b], [c, d]]

    cifrado = cifrar_hill(texto, matriz)
    mostrar(texto, matriz, cifrado, decifrar_hill(cifrado, matriz))
    print("  Inversa     :", matriz_inversa(matriz))


def transposicao():
    titulo("Cifra de Transposição  |  as letras só mudam de lugar")
    texto = perguntar("Texto", MENSAGEM)
    chave = perguntar("Chave", "SENHA")

    cifrado = cifrar_transposicao(texto, chave)
    mostrar(texto, chave, cifrado, decifrar_transposicao(cifrado, chave))

    chave = preparar_chave(chave)
    print("\n  Grade (lida por coluna, na ordem alfabética da chave):")
    print("   ", " ".join(chave))

    for linha in montar_grade(preparar_texto(texto), len(chave)):
        print("   ", " ".join(linha))


def fluxo():
    titulo("Cifra de Fluxo  |  C[i] = (P[i] + fluxo[i]) mod 26")
    texto = perguntar("Texto", MENSAGEM)
    semente = perguntar_numero("Chave (semente)", 2026)

    cifrado = cifrar_fluxo(texto, semente)
    mostrar(texto, semente, cifrado, decifrar_fluxo(cifrado, semente))
    print("  Fluxo       :", gerar_fluxo(semente, 10), "...")


def todas():
    titulo("A mensagem interceptada em todas as cifras")
    texto = perguntar("Texto", MENSAGEM)

    print()
    print("  Texto claro            :", preparar_texto(texto))
    print("  César (3)              :", cifrar_cesar(texto, 3))
    print("  Substituição (QWERTY)  :", cifrar_substituicao(texto, "QWERTYUIOPASDFGHJKLZXCVBNM"))
    print("  Afim (5, 8)            :", cifrar_afim(texto, 5, 8))
    print("  Vigenère (SEGREDO)     :", cifrar_vigenere(texto, "SEGREDO"))
    print("  Hill ([[3, 3], [2, 5]]):", cifrar_hill(texto, [[3, 3], [2, 5]]))
    print("  Transposição (SENHA)   :", cifrar_transposicao(texto, "SENHA"))
    print("  Fluxo (2026)           :", cifrar_fluxo(texto, 2026))


PASTA_EXPERIMENTO = "experimento"

DOCUMENTO_EXEMPLO = """CONTRATO DE PRESTACAO DE SERVICOS - CONFIDENCIAL
Cliente: ACME Ltda.
Valor: R$ 250.000,00
Este documento nao pode ser divulgado a terceiros.
"""


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


def experimento():
    titulo("Experimento  |  original -> AES -> cifrado -> AES -> original")
    os.makedirs(PASTA_EXPERIMENTO, exist_ok=True)

    caminho = perguntar("Arquivo original", os.path.join(PASTA_EXPERIMENTO, "documento.txt"))

    if not os.path.exists(caminho):
        if caminho != os.path.join(PASTA_EXPERIMENTO, "documento.txt"):
            raise ValueError(f"arquivo '{caminho}' nao encontrado")

        gravar_arquivo(caminho, DOCUMENTO_EXEMPLO.encode("utf-8"))
        print("  (criei um documento de exemplo)")

    cifrado = caminho + ".aes"
    restaurado = os.path.join(PASTA_EXPERIMENTO, "restaurado_" + os.path.basename(caminho))
    chave = gerar_chave(16)

    cifrar_arquivo(caminho, cifrado, chave, "AES")
    decifrar_arquivo(cifrado, restaurado, chave, "AES")

    original_bytes = ler_arquivo(caminho)
    cifrado_bytes = ler_arquivo(cifrado)

    print()
    print("  Chave AES-128 (hex)  :", chave.hex())
    print("  1) Original          :", caminho, f"({len(original_bytes)} bytes)")
    print("     começa com        :", original_bytes[:32])
    print("  2) Cifrado (IV+CBC)  :", cifrado, f"({len(cifrado_bytes)} bytes)")
    print("     começa com (hex)  :", cifrado_bytes[:32].hex())
    print("  3) Restaurado        :", restaurado)
    print()
    print("  SHA-256 original     :", hash_arquivo(caminho))
    print("  SHA-256 restaurado   :", hash_arquivo(restaurado))
    print("  Arquivos idênticos?  :", "SIM" if hash_arquivo(caminho) == hash_arquivo(restaurado) else "NAO")

    print()
    print("  Prova de que a chave importa:")

    try:
        decifrar_cbc(cifrado_bytes, gerar_chave(16), "AES")
        print("  chave errada         : (por acaso o padding passou, mas o conteudo e lixo)")
    except ValueError as erro:
        print("  chave errada         : ERRO ->", erro)


OPCOES = {
    "1": cesar,
    "2": substituicao,
    "3": afim,
    "4": vigenere,
    "5": hill,
    "6": transposicao,
    "7": fluxo,
    "8": todas,
    "9": des,
    "10": rc5,
    "11": aes,
    "12": comparar,
    "13": experimento,
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
