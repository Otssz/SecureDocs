from .euclides_estendido import euclides_estendido


def inverso_multiplicativo(a, m):
    if m < 1:
        raise ValueError(f"o modulo deve ser >= 1, recebi {m}")

    a = a % m

    mdc, x, y = euclides_estendido(a, m)

    if mdc != 1:
        return None

    return x % m
