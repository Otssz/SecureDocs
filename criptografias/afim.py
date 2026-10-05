from securedocs_math import mdc, inverso_multiplicativo, soma_modular, multiplicacao_modular

from .alfabeto import preparar_texto, letra_para_numero, numero_para_letra


def validar_chave_afim(a):
    if mdc(a, 26) != 1:
        raise ValueError(f"a={a} nao serve: mdc({a}, 26) = {mdc(a, 26)}, mas precisa ser 1")


def cifrar_afim(texto, a, b):
    validar_chave_afim(a)
    cifrado = ""

    for letra in preparar_texto(texto):
        p = letra_para_numero(letra)
        cifrado += numero_para_letra(soma_modular(a * p, b, 26))

    return cifrado


def decifrar_afim(texto, a, b):
    validar_chave_afim(a)
    a_inverso = inverso_multiplicativo(a, 26)
    claro = ""

    for letra in preparar_texto(texto):
        c = letra_para_numero(letra)
        claro += numero_para_letra(multiplicacao_modular(a_inverso, c - b, 26))

    return claro
