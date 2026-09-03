def euclides_estendido(a, b):
    if b == 0:
        return a, 1, 0

    mdc, x1, y1 = euclides_estendido(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return mdc, x, y