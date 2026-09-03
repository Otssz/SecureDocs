"""
MDC e o algoritmo de Euclides — o algoritmo mais antigo ainda em uso.

O Máximo Divisor Comum (MDC) de dois números é o maior número que divide os
dois ao mesmo tempo. Escrito por Euclides por volta de 300 a.C., o algoritmo
que o calcula continua sendo executado hoje, bilhões de vezes por dia, dentro
de cada conexão HTTPS.

A ideia central cabe em uma linha:

    mdc(a, b) = mdc(b, a mod b)

Ou seja: trocar o par por um par menor com o MESMO MDC, até o resto ser zero.

Por que o SecureDocs precisa disso? Porque `mdc(a, n) == 1` é a condição exata
para que `a` tenha inverso módulo `n` — e sem inverso não existe "decifrar".
No RSA, é o teste que valida a escolha da chave pública.
"""


def mdc(a: int, b: int) -> int:
    """
    Máximo Divisor Comum pelo algoritmo de Euclides (versão iterativa).

    A cada volta, trocamos (a, b) por (b, a mod b). O resto encolhe rápido,
    então o algoritmo termina em pouquíssimos passos mesmo para números
    gigantes: no pior caso, cerca de 5x o número de dígitos do menor deles.

    Trabalhamos com os valores absolutos porque o MDC é sempre positivo.

        >>> mdc(48, 18)
        6
        >>> mdc(17, 5)
        1
        >>> mdc(0, 7)
        7
        >>> mdc(-48, 18)
        6
    """
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def mdc_recursivo(a: int, b: int) -> int:
    """
    Mesmo algoritmo, escrito do jeito que a definição fala.

    Serve para mostrar na apresentação que a recursão é a tradução literal da
    identidade mdc(a, b) = mdc(b, a mod b), com caso base mdc(a, 0) = a.

        >>> mdc_recursivo(48, 18)
        6
        >>> mdc_recursivo(270, 192)
        6
    """
    a, b = abs(a), abs(b)
    if b == 0:
        return a
    return mdc_recursivo(b, a % b)


def passos_euclides(a: int, b: int) -> list[tuple[int, int, int, int]]:
    """
    Executa o algoritmo guardando cada divisão, para mostrar a conta na tela.

    Cada passo é a tupla (a, b, quociente, resto), lida como:

        a = quociente * b + resto

        >>> for a, b, q, r in passos_euclides(48, 18):
        ...     print(f"{a} = {q} * {b} + {r}")
        48 = 2 * 18 + 12
        18 = 1 * 12 + 6
        12 = 2 * 6 + 0

    O último `b` diferente de zero (aqui, 6) é o MDC.
    """
    a, b = abs(a), abs(b)
    passos = []
    while b != 0:
        quociente, resto = divmod(a, b)
        passos.append((a, b, quociente, resto))
        a, b = b, resto
    return passos


def mdc_por_forca_bruta(a: int, b: int) -> int:
    """
    Versão ingênua: testa todo divisor de 1 até o menor dos dois números.

    Existe apenas para comparação. Dá o mesmo resultado, mas o custo cresce
    com o VALOR dos números, não com a quantidade de dígitos. Para os números
    de 600 dígitos usados no RSA, isso nunca terminaria — enquanto o
    algoritmo de Euclides responde instantaneamente.

        >>> mdc_por_forca_bruta(48, 18)
        6
        >>> mdc_por_forca_bruta(48, 18) == mdc(48, 18)
        True
    """
    a, b = abs(a), abs(b)
    if a == 0 or b == 0:
        return a or b
    maior = 1
    for divisor in range(1, min(a, b) + 1):
        if a % divisor == 0 and b % divisor == 0:
            maior = divisor
    return maior


def mmc(a: int, b: int) -> int:
    """
    Mínimo Múltiplo Comum, calculado a partir do MDC.

    Usa a identidade |a * b| = mdc(a, b) * mmc(a, b). Dividimos antes de
    multiplicar para não inflar o número intermediário.

        >>> mmc(4, 6)
        12
        >>> mmc(21, 6)
        42
        >>> mmc(0, 5)
        0
    """
    if a == 0 or b == 0:
        return 0
    return abs(a // mdc(a, b) * b)


def sao_coprimos(a: int, b: int) -> bool:
    """
    Dois números são coprimos (primos entre si) quando mdc(a, b) == 1.

    Não precisam ser primos: 8 e 9 são compostos, mas não compartilham
    nenhum fator. Este é o teste que o RSA faz para aceitar o expoente
    público `e`: só se mdc(e, φ(n)) == 1 existe chave privada.

        >>> sao_coprimos(8, 9)
        True
        >>> sao_coprimos(8, 12)
        False
        >>> sao_coprimos(65537, 3120)
        True
    """
    return mdc(a, b) == 1


def divisores(n: int) -> list[int]:
    """
    Todos os divisores positivos de n, em ordem crescente.

    Percorre só até a raiz de n: cada divisor `d` encontrado entrega de graça
    o par `n // d`. Ajuda a enxergar por que um primo é "indivisível" — sua
    lista tem exatamente dois elementos.

        >>> divisores(28)
        [1, 2, 4, 7, 14, 28]
        >>> divisores(13)
        [1, 13]
    """
    if n <= 0:
        raise ValueError("n deve ser positivo")
    encontrados = set()
    d = 1
    while d * d <= n:
        if n % d == 0:
            encontrados.add(d)
            encontrados.add(n // d)
        d += 1
    return sorted(encontrados)
