import secrets


def gerar_chave(tamanho_bytes=16):
    return secrets.token_bytes(tamanho_bytes)


def xor_bytes(a, b):
    if len(a) != len(b):
        raise ValueError("os dois blocos precisam ter o mesmo tamanho")

    return bytes(x ^ y for x, y in zip(a, b))


def aplicar_padding(dados, tamanho_bloco):
    # PKCS#7: acrescenta N bytes, todos com o valor N (sempre acrescenta algo)
    n = tamanho_bloco - (len(dados) % tamanho_bloco)

    return dados + bytes([n]) * n


def remover_padding(dados, tamanho_bloco):
    if len(dados) == 0 or len(dados) % tamanho_bloco != 0:
        raise ValueError("tamanho invalido: dado cifrado corrompido")

    n = dados[-1]

    if n < 1 or n > tamanho_bloco or dados[-n:] != bytes([n]) * n:
        raise ValueError("padding invalido: chave errada ou dado corrompido")

    return dados[:-n]


def dividir_blocos(dados, tamanho_bloco):
    blocos = []

    for i in range(0, len(dados), tamanho_bloco):
        blocos.append(dados[i:i + tamanho_bloco])

    return blocos
