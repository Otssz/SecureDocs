from securedocs_math import subtracao_modular
from criptografias import ALFABETO, preparar_texto, letra_para_numero, decifrar_cesar

FREQUENCIAS_PORTUGUES = {
    "A": 14.63, "B": 1.04, "C": 3.88, "D": 4.99, "E": 12.57, "F": 1.02, "G": 1.30,
    "H": 1.28, "I": 6.18, "J": 0.40, "K": 0.02, "L": 2.78, "M": 4.74, "N": 5.05,
    "O": 10.73, "P": 2.52, "Q": 1.20, "R": 6.53, "S": 7.81, "T": 4.34, "U": 4.63,
    "V": 1.67, "W": 0.01, "X": 0.21, "Y": 0.01, "Z": 0.47,
}


def contar_frequencias(texto):
    texto = preparar_texto(texto)

    if texto == "":
        raise ValueError("o texto precisa ter pelo menos uma letra")

    frequencias = {}

    for letra in ALFABETO:
        frequencias[letra] = 100 * texto.count(letra) / len(texto)

    return frequencias


def letra_mais_frequente(texto):
    frequencias = contar_frequencias(texto)

    return max(frequencias, key=frequencias.get)


def pontuacao_portugues(texto):
    frequencias = contar_frequencias(texto)
    pontuacao = 0

    for letra in ALFABETO:
        esperado = FREQUENCIAS_PORTUGUES[letra]
        pontuacao += (frequencias[letra] - esperado) ** 2 / esperado

    return pontuacao


def quebrar_cesar_por_frequencia(cifrado):
    letra = letra_mais_frequente(cifrado)
    chave = subtracao_modular(letra_para_numero(letra), letra_para_numero("A"), 26)

    return chave, decifrar_cesar(cifrado, chave)
