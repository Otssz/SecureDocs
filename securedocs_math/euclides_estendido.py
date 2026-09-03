def euclides_estendido(a, b):
    if a < 0 or b < 0:
        mdc, x, y = euclides_estendido(abs(a), abs(b))

        return mdc, -x if a < 0 else x, -y if b < 0 else y

    if b == 0:
        return a, 1, 0

    mdc, x1, y1 = euclides_estendido(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return mdc, x, y
