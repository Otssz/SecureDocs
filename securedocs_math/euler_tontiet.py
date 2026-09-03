from .mdc import mdc


def phi(n):
    if n < 1:
        raise ValueError(f"phi so e definida para n >= 1, recebi {n}")

    contador = 0

    for i in range(1, n + 1):
        if mdc(i, n) == 1:
            contador += 1

    return contador
