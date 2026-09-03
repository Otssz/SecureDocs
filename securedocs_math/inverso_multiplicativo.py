from .euclides_estendido import euclides_estendido


def inverso_multiplicativo(a, m):
    mdc, x, y = euclides_estendido(a, m)

    if mdc != 1:
        return None

    return x % m