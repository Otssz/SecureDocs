# SecureDocs

Arquitetura criptográfica do sistema **SecureDocs**, da empresa fictícia **TechSecure**.

O SecureDocs guarda e troca documentos confidenciais (contratos, relatórios
financeiros, documentos pessoais), mas a primeira versão foi escrita sem
**nenhum** mecanismo criptográfico: mensagens em texto claro, documentos sem
criptografia e senhas salvas direto no banco.

Nossa equipe foi contratada para transformar o sistema em algo capaz de garantir:

| Propriedade | Pergunta que ela responde |
|---|---|
| **Confidencialidade** | quem consegue ler o documento? |
| **Integridade** | o documento foi modificado? |
| **Autenticidade** | quem realmente enviou isso? |
| **Não repúdio** | o remetente pode negar que enviou? |

O sistema evolui a cada missão da disciplina. Este repositório acompanha essa
evolução: uma missão, um conjunto de PRs.

---

## Missão 1 — Precisamos de matemática

> Como a matemática pode permitir a construção de sistemas criptográficos seguros?

Antes de escolher algoritmos, precisamos das operações que eles usam por baixo.
Toda a criptografia assimétrica (RSA, Diffie-Hellman, ElGamal) é aritmética com
números inteiros gigantes dentro de um universo finito.

Entregável: o subpacote [`securedocs/numeros`](securedocs/numeros).

| Módulo | Conteúdo | Responsável |
|---|---|---|
| `modular.py` | aritmética modular, congruências, classes residuais | Tiago |
| `euclides.py` | MDC, algoritmo de Euclides, MMC, coprimalidade | Ana Luiza |
| `estendido.py` | Euclides estendido, identidade de Bézout, inverso multiplicativo | Luiza |
| `primos.py` + `euler.py` | primos, crivo, fatoração, Miller-Rabin, função φ de Euler | Maria Júlia |
| `potencia.py` + `tcr.py` | exponenciação modular, teorema chinês do resto | Otávio |
| `demo.py` | integração: os 7 módulos montando um RSA didático | Grupo |

## Como usar

Não há dependências externas — só a biblioteca padrão do Python (3.9+).

```bash
git clone https://github.com/Otssz/SecureDocs.git
cd SecureDocs
python -m securedocs.demo
```

```python
from securedocs.numeros import mdc, inverso_modular, exp_modular

mdc(48, 18)                 # 6
inverso_modular(7, 26)      # 15   (porque 7 * 15 = 105 = 4*26 + 1)
exp_modular(7, 128, 13)     # 9    (calcula 7^128 mod 13 sem gerar 7^128)
```

## Organização do repositório

```
securedocs/
    __init__.py
    numeros/          <- Missão 1 (teoria dos números)
    demo.py           <- demonstração ponta a ponta
```

Cada nova missão entra como um novo subpacote dentro de `securedocs/`,
sem quebrar o que já está pronto.

## Fluxo de trabalho

- `main` é sempre estável: só recebe código via Pull Request.
- Uma branch por assunto: `feat/<assunto>`.
- Um PR por pessoa, revisado por pelo menos um colega antes do merge.
