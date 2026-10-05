from .alfabeto import ALFABETO, preparar_texto


def validar_chave_substituicao(chave):
    chave = preparar_texto(chave)

    if sorted(chave) != list(ALFABETO):
        raise ValueError("a chave deve ter as 26 letras do alfabeto, cada uma uma unica vez")

    return chave


def cifrar_substituicao(texto, chave):
    chave = validar_chave_substituicao(chave)
    cifrado = ""

    for letra in preparar_texto(texto):
        cifrado += chave[ALFABETO.index(letra)]

    return cifrado


def decifrar_substituicao(texto, chave):
    chave = validar_chave_substituicao(chave)
    claro = ""

    for letra in preparar_texto(texto):
        claro += ALFABETO[chave.index(letra)]

    return claro
