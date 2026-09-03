from securedocs_math import *


print("=== Aritmética Modular ===")
print(soma_modular(7, 5, 6))
print(subtracao_modular(7, 5, 6))
print(multiplicacao_modular(7, 5, 6))


print("\n=== MDC ===")
print(mdc(48, 18))


print("\n=== Algoritmo de Euclides ===")
print(algoritmo_euclides(48, 18))


print("\n=== Euclides Estendido ===")
resultado = euclides_estendido(48, 18)
print(resultado)


print("\n=== Inverso Multiplicativo ===")
print(inverso_multiplicativo(3, 7))


print("\n=== Números Primos ===")
print(eh_primo(7))
print(eh_primo(10))


print("\n=== Função Phi de Euler ===")
print(phi(8))


print("\n=== Exponenciação Modular ===")
print(exponenciacao_modular(2, 5, 7))


print("\n=== Teorema Chinês do Resto ===")
print(teorema_chines_resto(2, 3, 3, 5))