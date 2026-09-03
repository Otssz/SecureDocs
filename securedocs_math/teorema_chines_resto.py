from .inverso_multiplicativo import inverso_multiplicativo


def teorema_chines_resto(a1, m1, a2, m2):
    M = m1 * m2

    M1 = M // m1
    M2 = M // m2

    inverso1 = inverso_multiplicativo(M1, m1)
    inverso2 = inverso_multiplicativo(M2, m2)

    x = (a1 * M1 * inverso1 + a2 * M2 * inverso2) % M

    return x