from .mdc import mdc
from .inverso_multiplicativo import inverso_multiplicativo


def teorema_chines_resto(a1, m1, a2, m2):
    if m1 < 1 or m2 < 1:
        raise ValueError(f"os modulos devem ser >= 1, recebi {m1} e {m2}")

    if mdc(m1, m2) != 1:
        raise ValueError(
            f"m1={m1} e m2={m2} nao sao coprimos (mdc={mdc(m1, m2)}); "
            "o teorema chines do resto exige mdc(m1, m2) == 1"
        )

    M = m1 * m2

    M1 = M // m1
    M2 = M // m2

    inverso1 = inverso_multiplicativo(M1, m1)
    inverso2 = inverso_multiplicativo(M2, m2)

    x = (a1 * M1 * inverso1 + a2 * M2 * inverso2) % M

    return x
