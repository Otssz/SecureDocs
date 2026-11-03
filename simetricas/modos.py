# Modo CBC (Cipher Block Chaining) + padding PKCS#7 para qualquer cifra de bloco.
# Uma cifra de bloco sozinha so cifra UM bloco; o modo diz como cifrar mensagens maiores.
#   C[0] = E(P[0] XOR IV)      C[i] = E(P[i] XOR C[i-1])

from . import des, aes, rc5
from .utils import gerar_chave, xor_bytes, aplicar_padding, remover_padding, dividir_blocos

# nome -> (tamanho do bloco, expandir chave, cifrar bloco, decifrar bloco, tamanho de chave padrao)
ALGORITMOS = {
    "DES": (des.TAMANHO_BLOCO, des.expandir_chave_des, des.cifrar_bloco_des, des.decifrar_bloco_des, 8),
    "RC5": (rc5.TAMANHO_BLOCO, rc5.expandir_chave_rc5, rc5.cifrar_bloco_rc5, rc5.decifrar_bloco_rc5, 16),
    "AES": (aes.TAMANHO_BLOCO, aes.expandir_chave_aes, aes.cifrar_bloco_aes, aes.decifrar_bloco_aes, 16),
}


def obter_algoritmo(nome):
    nome = nome.upper()

    if nome not in ALGORITMOS:
        raise ValueError(f"algoritmo '{nome}' desconhecido; use {', '.join(ALGORITMOS)}")

    return ALGORITMOS[nome]


def gerar_iv(nome="AES"):
    return gerar_chave(obter_algoritmo(nome)[0])


def cifrar_cbc(dados, chave, nome="AES", iv=None):
    # devolve IV + texto cifrado (o IV nao e segredo, mas precisa ser aleatorio e novo a cada cifragem)
    tamanho, expandir, cifrar_bloco, _, _ = obter_algoritmo(nome)
    chaves = expandir(chave)

    if iv is None:
        iv = gerar_iv(nome)

    if len(iv) != tamanho:
        raise ValueError(f"o IV de {nome} deve ter {tamanho} bytes")

    anterior = iv
    cifrado = b""

    for bloco in dividir_blocos(aplicar_padding(dados, tamanho), tamanho):
        anterior = cifrar_bloco(xor_bytes(bloco, anterior), chaves)
        cifrado += anterior

    return iv + cifrado


def decifrar_cbc(dados, chave, nome="AES"):
    tamanho, expandir, _, decifrar_bloco, _ = obter_algoritmo(nome)
    chaves = expandir(chave)

    if len(dados) < 2 * tamanho:
        raise ValueError("dado cifrado curto demais")

    anterior = dados[:tamanho]
    claro = b""

    for bloco in dividir_blocos(dados[tamanho:], tamanho):
        claro += xor_bytes(decifrar_bloco(bloco, chaves), anterior)
        anterior = bloco

    return remover_padding(claro, tamanho)
