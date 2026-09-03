def exponenciacao_modular(base, expoente, modulo):
    if modulo < 1:
        raise ValueError(f"o modulo deve ser >= 1, recebi {modulo}")

    if expoente < 0:
        raise ValueError(f"o expoente deve ser >= 0, recebi {expoente}")

    resultado = 1 % modulo

    for i in range(expoente):
        resultado = (resultado * base) % modulo

    return resultado
