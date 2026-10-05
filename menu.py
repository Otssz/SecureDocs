import random

from criptografias import *
from criptografias.ataques import *

MENSAGEM = "TRANSFERIR DOCUMENTO PARA SERVIDOR CENTRAL"

CONTRATO = (
    "CONTRATO DE PRESTAÇÃO DE SERVIÇOS. A TechSecure, chamada de contratante, e a empresa "
    "parceira, chamada de contratada, acordam as cláusulas a seguir. A contratada fará a guarda "
    "e a transferência dos documentos da contratante para o servidor central e manterá sigilo "
    "sobre todas as informações recebidas. O valor mensal acordado será pago até o quinto dia "
    "útil de cada mês. Qualquer alteração neste contrato deverá ser aprovada por escrito pelas "
    "duas partes. A quebra de sigilo, a perda ou a alteração de documentos sem autorização "
    "causará multa e a rescisão imediata deste contrato."
)

MENU = """
============================================================
  SecureDocs - Missão 2: A mensagem interceptada
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

  ATAQUES
    9 - Força bruta na César
   10 - Força bruta na Afim
   11 - Análise de frequência na César

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


def ataque_cesar():
    titulo("ATAQUE: força bruta na César (26 chaves)")
    texto = perguntar("Texto", MENSAGEM)
    chave_secreta = random.randint(1, 25)
    cifrado = cifrar_cesar(texto, chave_secreta)
    print("\n  O invasor interceptou:", cifrado, "\n")

    tentativas = forca_bruta_cesar(cifrado)
    melhor_chave = tentativas[0][1]

    for chave in range(26):
        marca = ""

        if chave == melhor_chave:
            marca = "  <-- parece português!"

        print(f"  chave {chave:2}: {decifrar_cesar(cifrado, chave)}{marca}")

    print("\n  Chave encontrada:", melhor_chave)
    print("  Chave sorteada  :", chave_secreta)


def ataque_afim():
    titulo("ATAQUE: força bruta na Afim (12 x 26 = 312 chaves)")
    texto = perguntar("Texto", MENSAGEM)
    a = random.choice(chaves_validas_afim())
    b = random.randint(0, 25)
    cifrado = cifrar_afim(texto, a, b)
    print("\n  O invasor interceptou:", cifrado)

    tentativas = forca_bruta_afim(cifrado)
    print("  Chaves testadas:", len(tentativas))
    print("\n  As 3 tentativas mais parecidas com português (menor pontuação):")

    for pontuacao, chave, decifrado in tentativas[:3]:
        print(f"  a, b = {str(chave):9} pontuação {pontuacao:6.1f}  {decifrado}")

    print("\n  Chave encontrada:", tentativas[0][1])
    print("  Chave sorteada  :", (a, b))


def ataque_frequencia():
    titulo("ATAQUE: análise de frequência na César")
    texto = input("Texto [Enter = contrato da TechSecure]: ").strip()

    if texto == "":
        texto = CONTRATO

    chave_secreta = random.randint(1, 25)
    cifrado = cifrar_cesar(texto, chave_secreta)
    print(f"\n  O invasor interceptou ({len(cifrado)} letras): {cifrado[:60]}...\n")

    frequencias = contar_frequencias(cifrado)
    print("  Letra   No cifrado                 Em português")

    for letra in ALFABETO:
        no_cifrado = frequencias[letra]
        em_portugues = FREQUENCIAS_PORTUGUES[letra]
        barra1 = "#" * round(no_cifrado)
        barra2 = "#" * round(em_portugues)
        print(f"    {letra}   {no_cifrado:5.1f}% {barra1:20} {em_portugues:5.1f}% {barra2}")

    letra = letra_mais_frequente(cifrado)
    chave, decifrado = quebrar_cesar_por_frequencia(cifrado)

    print(f"\n  A letra mais comum no cifrado é {letra}; em português é A.")
    print(f"  Então a chave provável é {letra} - A = {chave}")
    print("  Chave sorteada:", chave_secreta)
    print(f"\n  Texto decifrado: {decifrado[:120]}...")


OPCOES = {
    "1": cesar,
    "2": substituicao,
    "3": afim,
    "4": vigenere,
    "5": hill,
    "6": transposicao,
    "7": fluxo,
    "8": todas,
    "9": ataque_cesar,
    "10": ataque_afim,
    "11": ataque_frequencia,
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
