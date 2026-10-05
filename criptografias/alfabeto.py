ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

SEM_ACENTO = str.maketrans("ÁÀÂÃÉÊÍÓÔÕÚÜÇ", "AAAAEEIOOOUUC")


def preparar_texto(texto):
    texto = texto.upper().translate(SEM_ACENTO)
    resultado = ""

    for letra in texto:
        if letra in ALFABETO:
            resultado += letra

    return resultado


def preparar_chave(chave):
    chave = preparar_texto(chave)

    if chave == "":
        raise ValueError("a chave precisa ter pelo menos uma letra")

    return chave


def letra_para_numero(letra):
    return ALFABETO.index(letra)


def numero_para_letra(numero):
    return ALFABETO[numero]
