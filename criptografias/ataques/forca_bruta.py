from securedocs_math import mdc
from criptografias import decifrar_cesar, decifrar_afim

from .analise_frequencia import pontuacao_portugues


def forca_bruta_cesar(cifrado):
    tentativas = []

    for chave in range(26):
        texto = decifrar_cesar(cifrado, chave)
        tentativas.append((pontuacao_portugues(texto), chave, texto))

    tentativas.sort()

    return tentativas


def chaves_validas_afim():
    valores = []

    for a in range(1, 26):
        if mdc(a, 26) == 1:
            valores.append(a)

    return valores


def forca_bruta_afim(cifrado):
    tentativas = []

    for a in chaves_validas_afim():
        for b in range(26):
            texto = decifrar_afim(cifrado, a, b)
            tentativas.append((pontuacao_portugues(texto), (a, b), texto))

    tentativas.sort()

    return tentativas
