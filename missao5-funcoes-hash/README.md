# securedocs_hash — Biblioteca de funções hash (SecureDocs · Missão 5)

Biblioteca didática em **Python puro** (sem dependências) com implementações próprias de
funções hash criptográficas, ferramentas de integridade de documentos e demonstrações de
ataques. Feita para responder à pergunta da TechSecure:

> *Como verificar se um documento recebido é exatamente igual ao documento enviado?*

## Algoritmos implementados do zero

| Família | Algoritmos | Construção | Situação |
|---|---|---|---|
| MD5 | `md5` | Merkle–Damgård | **Quebrado** (colisões em segundos) |
| SHA-1 | `sha1` | Merkle–Damgård | **Quebrado** (SHAttered, 2017) |
| SHA-2 | `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256` | Merkle–Damgård | Seguro |
| SHA-3 | `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`, `shake_128`, `shake_256` | Esponja (Keccak-f[1600]) | Seguro |
| MAC | `HMAC` (com qualquer hash acima) | RFC 2104 | Seguro |

As constantes do SHA-2 (raízes de primos) e do SHA-3 (LFSR e deslocamentos ρ) são
**calculadas a partir da definição** das normas, não copiadas de tabelas.

Todas as saídas são conferidas contra o `hashlib` (OpenSSL) e contra os vetores oficiais
(RFC 1321, FIPS 180-4, FIPS 202, RFC 4231).

## Estrutura

```
securedocs_hash/
├── _base.py       # rotações de bits, interface comum e construção Merkle–Damgård
├── md5.py         # MD5  (RFC 1321)
├── sha1.py        # SHA-1 (FIPS 180-4)
├── sha2.py        # SHA-224/256/384/512 e SHA-512/t (FIPS 180-4)
├── sha3.py        # Keccak-f[1600], SHA3-* e SHAKE (FIPS 202)
├── hmac.py        # HMAC e comparação em tempo constante
├── integrity.py   # hash de arquivos, verificação, comparação, manifesto autenticado
├── attacks.py     # avalanche, aniversário, extensão de comprimento, colisões reais
├── __main__.py    # linha de comando
└── dados/         # pares de colisão reais (MD5 gerado com fastcoll; SHA-1 SHAttered)
tests/test_hashes.py               # 16 testes automatizados
experimentos/experimento_missao5.py  # experimento completo da missão
```

## Uso como biblioteca

```python
import securedocs_hash as sh

sh.sha256(b"abc").hexdigest()
sh.new("sha3_256", b"abc").hexdigest()
sh.shake_256(b"abc").hexdigest(64)          # saída de tamanho variável

h = sh.sha256()                             # uso incremental (streaming)
h.update(b"parte 1"); h.update(b"parte 2")
h.hexdigest()

sh.hash_file("contrato.pdf", "sha256")
sh.verify_file("recebido.pdf", "a748505471...", "sha256")      # True / False
sh.compare_files("contrato.pdf", "recebido.pdf")               # inclui % de bits diferentes
sh.HMAC(b"chave", b"mensagem", "sha256").hexdigest()
```

## Uso pela linha de comando

```bash
python -m securedocs_hash listar
python -m securedocs_hash hash contrato.pdf -a todos
python -m securedocs_hash comparar contrato.pdf contrato_modificado.pdf
python -m securedocs_hash verificar recebido.pdf <hash_esperado> -a sha256
python -m securedocs_hash texto "Olá" -a sha3_256
python -m securedocs_hash hmac contrato.pdf --chave segredo
python -m securedocs_hash manifesto criar pasta_docs --chave segredo
python -m securedocs_hash manifesto verificar pasta_docs --chave segredo
python -m securedocs_hash avalanche -a sha256 -n 500
python -m securedocs_hash aniversario -a sha256 -b 24
```

## Testes e experimento

```bash
python tests/test_hashes.py          # ou: python -m pytest -v
python experimentos/experimento_missao5.py
```

O experimento precisa de `reportlab` (gera o contrato.pdf) e `matplotlib` (gráficos):
`pip install reportlab matplotlib`. Os resultados ficam em `experimentos/saida/`.

## Observações

* A implementação é **didática**: é centenas a milhares de vezes mais lenta que o `hashlib`.
  Em produção, o SecureDocs deve usar `hashlib` / OpenSSL.
* O par de colisão MD5 em `dados/` foi gerado com o *fastcoll* de Marc Stevens
  (HashClash). A licença do fastcoll não permite redistribuição, por isso o programa
  não acompanha a biblioteca — apenas os 192 bytes gerados.
* Os prefixos SHA-1 de 320 bytes vêm da colisão pública *SHAttered* (Stevens, Bursztein,
  Karpman, Albertini e Markov, 2017).
