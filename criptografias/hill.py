from securedocs_math import mdc, inverso_multiplicativo, soma_modular, subtracao_modular, multiplicacao_modular

from .alfabeto import preparar_texto, letra_para_numero, numero_para_letra


def validar_chave_hill(matriz):
    [a, b], [c, d] = matriz
    det = subtracao_modular(a * d, b * c, 26)

    if mdc(det, 26) != 1:
        raise ValueError(f"matriz invalida: det = {det} e mdc({det}, 26) = {mdc(det, 26)}, entao ela nao tem inversa")

    return det


def matriz_inversa(matriz):
    det = validar_chave_hill(matriz)
    det_inverso = inverso_multiplicativo(det, 26)
    [a, b], [c, d] = matriz

    return [
        [multiplicacao_modular(det_inverso, d, 26), multiplicacao_modular(det_inverso, -b, 26)],
        [multiplicacao_modular(det_inverso, -c, 26), multiplicacao_modular(det_inverso, a, 26)],
    ]


def multiplicar(matriz, texto):
    [a, b], [c, d] = matriz
    resultado = ""

    for i in range(0, len(texto), 2):
        x1 = letra_para_numero(texto[i])
        x2 = letra_para_numero(texto[i + 1])
        resultado += numero_para_letra(soma_modular(a * x1, b * x2, 26))
        resultado += numero_para_letra(soma_modular(c * x1, d * x2, 26))

    return resultado


def cifrar_hill(texto, matriz):
    validar_chave_hill(matriz)
    texto = preparar_texto(texto)

    if len(texto) % 2 == 1:
        texto += "X"

    return multiplicar(matriz, texto)


def decifrar_hill(texto, matriz):
    return multiplicar(matriz_inversa(matriz), preparar_texto(texto))
