def algoritmo_euclides(a, b):
    a, b = abs(a), abs(b)

    while b != 0:
        resto = a % b
        a = b
        b = resto

    return a
