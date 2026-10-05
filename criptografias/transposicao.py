from .alfabeto import preparar_texto, preparar_chave


def ordem_das_colunas(chave):
    return sorted(range(len(chave)), key=lambda coluna: chave[coluna])


def montar_grade(texto, largura):
    while len(texto) % largura != 0:
        texto += "X"

    grade = []

    for i in range(0, len(texto), largura):
        grade.append(texto[i:i + largura])

    return grade


def cifrar_transposicao(texto, chave):
    chave = preparar_chave(chave)
    grade = montar_grade(preparar_texto(texto), len(chave))
    cifrado = ""

    for coluna in ordem_das_colunas(chave):
        for linha in grade:
            cifrado += linha[coluna]

    return cifrado


def decifrar_transposicao(texto, chave):
    chave = preparar_chave(chave)
    texto = preparar_texto(texto)

    if len(texto) % len(chave) != 0:
        raise ValueError("o tamanho do texto cifrado deve ser multiplo do tamanho da chave")

    numero_de_linhas = len(texto) // len(chave)
    grade = []

    for i in range(numero_de_linhas):
        grade.append([""] * len(chave))

    posicao = 0

    for coluna in ordem_das_colunas(chave):
        for linha in grade:
            linha[coluna] = texto[posicao]
            posicao += 1

    claro = ""

    for linha in grade:
        claro += "".join(linha)

    return claro
