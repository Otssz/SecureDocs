from securedocs_math import soma_modular, subtracao_modular

from .alfabeto import preparar_texto, letra_para_numero, numero_para_letra


def cifrar_cesar(texto, chave):
    cifrado = ""

    for letra in preparar_texto(texto):
        p = letra_para_numero(letra)
        cifrado += numero_para_letra(soma_modular(p, chave, 26))

    return cifrado


def decifrar_cesar(texto, chave):
    claro = ""

    for letra in preparar_texto(texto):
        c = letra_para_numero(letra)
        claro += numero_para_letra(subtracao_modular(c, chave, 26))

    return claro
