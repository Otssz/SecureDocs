"""
Missão 1 — Precisamos de matemática.

Este subpacote reúne os algoritmos de teoria dos números que sustentam
os sistemas criptográficos modernos (RSA, Diffie-Hellman, ElGamal...).

Cada módulo é independente e pode ser lido/explicado isoladamente:

    modular.py     aritmética modular (congruências, classes residuais)
    euclides.py    MDC e algoritmo de Euclides
    estendido.py   algoritmo estendido de Euclides e inverso multiplicativo
    primos.py      números primos (teste, crivo, fatoração, geração)
    euler.py       função φ de Euler e teoremas de Euler/Fermat
    potencia.py    exponenciação modular rápida
    tcr.py         teorema chinês do resto

Os atalhos de importação são adicionados aqui na PR de integração.
"""
