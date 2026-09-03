"""
Aritmética modular — o "relógio" da criptografia.

Toda a criptografia assimétrica acontece dentro de um conjunto FINITO de
números: em vez de trabalhar com todos os inteiros, trabalhamos com os restos
da divisão por um número n (o módulo).

A analogia é o relógio: em um relógio de 12 horas, 15h é a mesma coisa que 3h,
porque 15 e 3 deixam o mesmo resto na divisão por 12. Escrevemos:

    15 ≡ 3 (mod 12)      "15 é congruente a 3, módulo 12"

Por que isso importa para o SecureDocs? Porque operar dentro de um conjunto
finito faz o resultado "embaralhar" e perder a pista do valor original.
Sabendo que x + k ≡ 7 (mod 12), não dá para deduzir x sem conhecer k.
"""


def _valida_modulo(n: int) -> None:
    """Garante que o módulo é válido. Módulo precisa ser um inteiro >= 1."""
    if not isinstance(n, int):
        raise TypeError(f"o módulo deve ser inteiro, recebi {type(n).__name__}")
    if n < 1:
        raise ValueError(f"o módulo deve ser >= 1, recebi {n}")


def resto(a: int, n: int) -> int:
    """
    Resto da divisão de `a` por `n`, sempre no intervalo [0, n).

    Esse é o "representante canônico" da classe de `a`: o número entre 0 e n-1
    que representa todo mundo que deixa o mesmo resto.

    Atenção com números negativos: em Python o operador % já devolve resultado
    não negativo (-7 % 5 == 3), mas em C, Java ou JavaScript ele devolveria -2.
    Como a criptografia não admite índice negativo, deixamos isso explícito.

        >>> resto(17, 5)
        2
        >>> resto(-7, 5)
        3
        >>> resto(20, 5)
        0
    """
    _valida_modulo(n)
    return a % n


def congruentes(a: int, b: int, n: int) -> bool:
    """
    Verifica se a ≡ b (mod n), ou seja, se `a` e `b` deixam o mesmo resto.

    Equivale a perguntar: n divide (a - b)?

        >>> congruentes(15, 3, 12)
        True
        >>> congruentes(15, 4, 12)
        False
        >>> congruentes(-1, 11, 12)
        True
    """
    _valida_modulo(n)
    return (a - b) % n == 0


def soma_mod(a: int, b: int, n: int) -> int:
    """
    Soma modular: (a + b) mod n.

        >>> soma_mod(9, 8, 12)   # 9h + 8h no relógio = 5h
        5
    """
    _valida_modulo(n)
    return (a + b) % n


def sub_mod(a: int, b: int, n: int) -> int:
    """
    Subtração modular: (a - b) mod n.

        >>> sub_mod(3, 8, 12)
        7
    """
    _valida_modulo(n)
    return (a - b) % n


def mul_mod(a: int, b: int, n: int) -> int:
    """
    Multiplicação modular: (a * b) mod n.

    Propriedade que sustenta os algoritmos rápidos: dá para reduzir ANTES de
    multiplicar. (a*b) mod n == ((a mod n) * (b mod n)) mod n. Isso evita que
    os números cresçam sem controle durante uma conta longa.

        >>> mul_mod(7, 8, 12)
        8
        >>> mul_mod(10**20, 10**20, 97) == (10**20 % 97) * (10**20 % 97) % 97
        True
    """
    _valida_modulo(n)
    return (a * b) % n


def classe_residual(a: int, n: int, quantidade: int = 5) -> list[int]:
    """
    Lista alguns membros da classe de equivalência de `a` módulo `n`.

    Todos esses números são "a mesma coisa" dentro da aritmética módulo n.

        >>> classe_residual(3, 12)
        [3, 15, 27, 39, 51]
        >>> classe_residual(15, 12)
        [3, 15, 27, 39, 51]
    """
    _valida_modulo(n)
    base = a % n
    return [base + k * n for k in range(quantidade)]


def conjunto_residuos(n: int) -> list[int]:
    """
    O conjunto Z_n = {0, 1, ..., n-1}: todos os restos possíveis módulo n.

    É o universo finito onde a criptografia acontece.

        >>> conjunto_residuos(5)
        [0, 1, 2, 3, 4]
    """
    _valida_modulo(n)
    return list(range(n))


def tabela_operacao(n: int, operacao: str = "*") -> list[list[int]]:
    """
    Monta a tabela de soma ou multiplicação módulo n.

    Útil para VER na apresentação por que o módulo primo é especial: com n
    primo, nenhuma linha (fora a do zero) tem zero — todo elemento é
    invertível. Com n composto aparecem zeros no meio da tabela, sinal de
    divisores de zero (ex.: 2 * 3 ≡ 0 mod 6).

        >>> for linha in tabela_operacao(4, "*"):
        ...     print(linha)
        [0, 0, 0, 0]
        [0, 1, 2, 3]
        [0, 2, 0, 2]
        [0, 3, 2, 1]
    """
    _valida_modulo(n)
    if operacao not in ("+", "*"):
        raise ValueError("operação deve ser '+' ou '*'")
    if operacao == "+":
        return [[(i + j) % n for j in range(n)] for i in range(n)]
    return [[(i * j) % n for j in range(n)] for i in range(n)]


def texto_para_numero(texto: str) -> int:
    """
    Converte um texto em um único inteiro, para poder ser cifrado.

    Criptografia assimétrica opera sobre NÚMEROS, não sobre texto. Então o
    primeiro passo para proteger um documento do SecureDocs é transformá-lo
    em um inteiro (aqui, lendo os bytes UTF-8 como um número em base 256).

        >>> texto_para_numero("Oi")
        20329
    """
    return int.from_bytes(texto.encode("utf-8"), "big")


def numero_para_texto(numero: int) -> str:
    """
    Operação inversa de `texto_para_numero`.

        >>> numero_para_texto(20329)
        'Oi'
        >>> numero_para_texto(texto_para_numero("contrato confidencial"))
        'contrato confidencial'
    """
    if numero < 0:
        raise ValueError("não existe texto para número negativo")
    tamanho = (numero.bit_length() + 7) // 8
    return numero.to_bytes(tamanho, "big").decode("utf-8")
