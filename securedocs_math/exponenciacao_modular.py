def exponenciacao_modular(base, expoente, modulo):
    resultado = 1

    for i in range(expoente):
        resultado = (resultado * base) % modulo

    return resultado