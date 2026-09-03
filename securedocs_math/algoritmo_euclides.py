def algoritmo_euclides(a, b):
    while b != 0:
        resto = a % b
        a = b
        b = resto

    return a