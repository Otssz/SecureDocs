def soma_modular(a, b, m):
    if m < 1:
        raise ValueError(f"o modulo deve ser >= 1, recebi {m}")

    return (a + b) % m


def subtracao_modular(a, b, m):
    if m < 1:
        raise ValueError(f"o modulo deve ser >= 1, recebi {m}")

    return (a - b) % m


def multiplicacao_modular(a, b, m):
    if m < 1:
        raise ValueError(f"o modulo deve ser >= 1, recebi {m}")

    return (a * b) % m

