# AES - Advanced Encryption Standard (FIPS 197)
# Bloco de 128 bits; chave de 128, 192 ou 256 bits (10, 12 ou 14 rodadas).
# Toda a aritmetica e feita no corpo finito GF(2^8), modulo x^8 + x^4 + x^3 + x + 1.

TAMANHO_BLOCO = 16
POLINOMIO = 0x11B


def multiplicar_gf(a, b):
    resultado = 0

    while b:
        if b & 1:
            resultado ^= a

        a <<= 1

        if a & 0x100:
            a ^= POLINOMIO

        b >>= 1

    return resultado


def inverso_gf(a):
    # em GF(2^8), a^255 = 1, entao o inverso de a e a^254
    if a == 0:
        return 0

    resultado = 1

    for _ in range(254):
        resultado = multiplicar_gf(resultado, a)

    return resultado


def rotacionar_byte(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def gerar_sbox():
    sbox = []

    for i in range(256):
        b = inverso_gf(i)
        s = b ^ rotacionar_byte(b, 1) ^ rotacionar_byte(b, 2) ^ rotacionar_byte(b, 3) ^ rotacionar_byte(b, 4) ^ 0x63
        sbox.append(s)

    return sbox


SBOX = gerar_sbox()
SBOX_INVERSA = [0] * 256

for _i in range(256):
    SBOX_INVERSA[SBOX[_i]] = _i

MATRIZ_MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
MATRIZ_MIX_INVERSA = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


# O estado e uma lista de 16 bytes; o byte na linha r, coluna c fica no indice 4*c + r.

def sub_bytes(estado, caixa):
    return [caixa[b] for b in estado]


def shift_rows(estado):
    novo = [0] * 16

    for c in range(4):
        for r in range(4):
            novo[4 * c + r] = estado[4 * ((c + r) % 4) + r]

    return novo


def shift_rows_inverso(estado):
    novo = [0] * 16

    for c in range(4):
        for r in range(4):
            novo[4 * ((c + r) % 4) + r] = estado[4 * c + r]

    return novo


def mix_columns(estado, matriz):
    novo = [0] * 16

    for c in range(4):
        coluna = estado[4 * c:4 * c + 4]

        for r in range(4):
            valor = 0

            for j in range(4):
                valor ^= multiplicar_gf(matriz[r][j], coluna[j])

            novo[4 * c + r] = valor

    return novo


def add_round_key(estado, chave_rodada):
    return [a ^ b for a, b in zip(estado, chave_rodada)]


def expandir_chave_aes(chave):
    if len(chave) not in (16, 24, 32):
        raise ValueError(f"a chave AES deve ter 16, 24 ou 32 bytes, recebi {len(chave)}")

    nk = len(chave) // 4
    nr = nk + 6
    palavras = [list(chave[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1

    for i in range(nk, 4 * (nr + 1)):
        temp = list(palavras[i - 1])

        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = multiplicar_gf(rcon, 2)
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]

        palavras.append([a ^ b for a, b in zip(palavras[i - nk], temp)])

    chaves_rodada = []

    for r in range(nr + 1):
        chave_rodada = []

        for palavra in palavras[4 * r:4 * r + 4]:
            chave_rodada += palavra

        chaves_rodada.append(chave_rodada)

    return chaves_rodada


def cifrar_bloco_aes(bloco, chaves_rodada):
    if len(bloco) != TAMANHO_BLOCO:
        raise ValueError(f"o bloco AES deve ter 16 bytes, recebi {len(bloco)}")

    nr = len(chaves_rodada) - 1
    estado = add_round_key(list(bloco), chaves_rodada[0])

    for r in range(1, nr):
        estado = sub_bytes(estado, SBOX)
        estado = shift_rows(estado)
        estado = mix_columns(estado, MATRIZ_MIX)
        estado = add_round_key(estado, chaves_rodada[r])

    estado = sub_bytes(estado, SBOX)
    estado = shift_rows(estado)
    estado = add_round_key(estado, chaves_rodada[nr])

    return bytes(estado)


def decifrar_bloco_aes(bloco, chaves_rodada):
    if len(bloco) != TAMANHO_BLOCO:
        raise ValueError(f"o bloco AES deve ter 16 bytes, recebi {len(bloco)}")

    nr = len(chaves_rodada) - 1
    estado = add_round_key(list(bloco), chaves_rodada[nr])

    for r in range(nr - 1, 0, -1):
        estado = shift_rows_inverso(estado)
        estado = sub_bytes(estado, SBOX_INVERSA)
        estado = add_round_key(estado, chaves_rodada[r])
        estado = mix_columns(estado, MATRIZ_MIX_INVERSA)

    estado = shift_rows_inverso(estado)
    estado = sub_bytes(estado, SBOX_INVERSA)
    estado = add_round_key(estado, chaves_rodada[0])

    return bytes(estado)
