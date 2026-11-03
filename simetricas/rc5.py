# RC5-w/r/b (Rivest, 1994) - aqui com w = 32 bits (bloco de 64 bits)
# Parametros: r = numero de rodadas (padrao 12), b = tamanho da chave em bytes (0 a 255).
# Usa so soma modular 2^32, XOR e rotacao dependente dos dados.

TAMANHO_BLOCO = 8
W = 32
MASCARA = 0xFFFFFFFF
P32 = 0xB7E15163  # Odd((e - 2) * 2^32)
Q32 = 0x9E3779B9  # Odd((phi - 1) * 2^32)


def rotacionar_esquerda(x, n):
    n = n % W

    return ((x << n) | (x >> (W - n))) & MASCARA


def rotacionar_direita(x, n):
    n = n % W

    return ((x >> n) | (x << (W - n))) & MASCARA


def expandir_chave_rc5(chave, rodadas=12):
    if len(chave) > 255:
        raise ValueError("a chave RC5 pode ter no maximo 255 bytes")

    if not 0 <= rodadas <= 255:
        raise ValueError("o numero de rodadas deve estar entre 0 e 255")

    # 1) copia a chave para um vetor L de palavras de 32 bits (little-endian)
    c = max(1, (len(chave) + 3) // 4)
    L = [0] * c

    for i in range(len(chave) - 1, -1, -1):
        L[i // 4] = ((L[i // 4] << 8) + chave[i]) & MASCARA

    # 2) inicializa a tabela S com as constantes magicas
    t = 2 * (rodadas + 1)
    S = [P32]

    for i in range(1, t):
        S.append((S[i - 1] + Q32) & MASCARA)

    # 3) mistura a chave com a tabela S
    A = B = i = j = 0

    for _ in range(3 * max(t, c)):
        A = S[i] = rotacionar_esquerda((S[i] + A + B) & MASCARA, 3)
        B = L[j] = rotacionar_esquerda((L[j] + A + B) & MASCARA, A + B)
        i = (i + 1) % t
        j = (j + 1) % c

    return S


def cifrar_bloco_rc5(bloco, S):
    if len(bloco) != TAMANHO_BLOCO:
        raise ValueError(f"o bloco RC5-32 deve ter 8 bytes, recebi {len(bloco)}")

    rodadas = len(S) // 2 - 1
    A = int.from_bytes(bloco[:4], "little")
    B = int.from_bytes(bloco[4:], "little")

    A = (A + S[0]) & MASCARA
    B = (B + S[1]) & MASCARA

    for i in range(1, rodadas + 1):
        A = (rotacionar_esquerda(A ^ B, B) + S[2 * i]) & MASCARA
        B = (rotacionar_esquerda(B ^ A, A) + S[2 * i + 1]) & MASCARA

    return A.to_bytes(4, "little") + B.to_bytes(4, "little")


def decifrar_bloco_rc5(bloco, S):
    if len(bloco) != TAMANHO_BLOCO:
        raise ValueError(f"o bloco RC5-32 deve ter 8 bytes, recebi {len(bloco)}")

    rodadas = len(S) // 2 - 1
    A = int.from_bytes(bloco[:4], "little")
    B = int.from_bytes(bloco[4:], "little")

    for i in range(rodadas, 0, -1):
        B = rotacionar_direita((B - S[2 * i + 1]) & MASCARA, A) ^ A
        A = rotacionar_direita((A - S[2 * i]) & MASCARA, B) ^ B

    B = (B - S[1]) & MASCARA
    A = (A - S[0]) & MASCARA

    return A.to_bytes(4, "little") + B.to_bytes(4, "little")
