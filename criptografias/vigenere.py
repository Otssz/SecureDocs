from securedocs_math import soma_modular, subtracao_modular

from .alfabeto import preparar_texto, preparar_chave, letra_para_numero, numero_para_letra


def cifrar_vigenere(texto, chave):
    texto = preparar_texto(texto)
    chave = preparar_chave(chave)
    cifrado = ""

    for i in range(len(texto)):
        p = letra_para_numero(texto[i])
        k = letra_para_numero(chave[i % len(chave)])
        cifrado += numero_para_letra(soma_modular(p, k, 26))

    return cifrado


def decifrar_vigenere(texto, chave):
    texto = preparar_texto(texto)
    chave = preparar_chave(chave)
    claro = ""

    for i in range(len(texto)):
        c = letra_para_numero(texto[i])
        k = letra_para_numero(chave[i % len(chave)])
        claro += numero_para_letra(subtracao_modular(c, k, 26))

    return claro
