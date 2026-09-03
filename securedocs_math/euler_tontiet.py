from .mdc import mdc


def phi(n):
    contador = 0

    for i in range(1, n + 1):
        if mdc(i, n) == 1:
            contador += 1

    return contador