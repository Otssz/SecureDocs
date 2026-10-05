from securedocs_math import soma_modular, subtracao_modular, multiplicacao_modular

from .alfabeto import preparar_texto, letra_para_numero, numero_para_letra


MULTIPLICADOR = 16807
MODULO = 2147483647


def gerar_fluxo(semente, quantidade):
    if semente < 1 or semente >= MODULO:
        raise ValueError(f"a semente deve estar entre 1 e {MODULO - 1}")

    fluxo = []
    numero = semente

    for i in range(quantidade):
        numero = multiplicacao_modular(MULTIPLICADOR, numero, MODULO)
        fluxo.append(numero % 26)

    return fluxo


def cifrar_fluxo(texto, semente):
    texto = preparar_texto(texto)
    fluxo = gerar_fluxo(semente, len(texto))
    cifrado = ""

    for i in range(len(texto)):
        p = letra_para_numero(texto[i])
        cifrado += numero_para_letra(soma_modular(p, fluxo[i], 26))

    return cifrado


def decifrar_fluxo(texto, semente):
    texto = preparar_texto(texto)
    fluxo = gerar_fluxo(semente, len(texto))
    claro = ""

    for i in range(len(texto)):
        c = letra_para_numero(texto[i])
        claro += numero_para_letra(subtracao_modular(c, fluxo[i], 26))

    return claro
