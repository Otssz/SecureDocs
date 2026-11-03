import hashlib

from .modos import cifrar_cbc, decifrar_cbc


def ler_arquivo(caminho):
    with open(caminho, "rb") as arquivo:
        return arquivo.read()


def gravar_arquivo(caminho, dados):
    with open(caminho, "wb") as arquivo:
        arquivo.write(dados)


def cifrar_arquivo(entrada, saida, chave, algoritmo="AES"):
    gravar_arquivo(saida, cifrar_cbc(ler_arquivo(entrada), chave, algoritmo))


def decifrar_arquivo(entrada, saida, chave, algoritmo="AES"):
    gravar_arquivo(saida, decifrar_cbc(ler_arquivo(entrada), chave, algoritmo))


def hash_arquivo(caminho):
    # so para comparar se dois arquivos sao identicos (nao faz parte da cifra)
    return hashlib.sha256(ler_arquivo(caminho)).hexdigest()
