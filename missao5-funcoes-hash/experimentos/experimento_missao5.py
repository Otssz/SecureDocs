"""
Experimento da Missão 5 – "O documento foi alterado".

Executar a partir da raiz do projeto:
    python experimentos/experimento_missao5.py

Gera, na pasta experimentos/saida/:
  * contrato.pdf              – documento original
  * contrato_modificado.pdf   – MESMO arquivo com UM ÚNICO byte/caractere trocado
  * resultados.json           – todos os números do experimento
  * graficos/*.png            – gráficos usados no relatório e na apresentação
  * colisoes/*                – contratos "envenenados" com MD5 e SHA-1 idênticos
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import securedocs_hash as sh                      # noqa: E402
from securedocs_hash import attacks               # noqa: E402

OUT = Path(__file__).parent / "saida"
GRAF = OUT / "graficos"
COL = OUT / "colisoes"
for d in (OUT, GRAF, COL):
    d.mkdir(parents=True, exist_ok=True)

ALGS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha512_256", "sha3_224", "sha3_256", "sha3_384", "sha3_512"]
R: dict = {}


def titulo(t):
    print("\n" + "=" * 78 + f"\n{t}\n" + "=" * 78)


# ---------------------------------------------------------------------------
# 1. Gerar o contrato.pdf (determinístico) e a versão com 1 caractere alterado
# ---------------------------------------------------------------------------
def gerar_contrato(path: Path, valor: str) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(str(path), pagesize=A4, pageCompression=0, invariant=1)
    c.setTitle("Contrato de Prestação de Serviços")
    w, h = A4
    y = h - 70
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(w / 2, y, "CONTRATO DE PRESTAÇÃO DE SERVIÇOS Nº 2026/0457")
    y -= 40
    linhas = [
        ("Helvetica", "CONTRATANTE: Construtora Horizonte Ltda., CNPJ fictício 00.000.000/0001-00."),
        ("Helvetica", "CONTRATADA: TechSecure Soluções em Segurança da Informação S.A."),
        ("Helvetica", ""),
        ("Helvetica-Bold", "CLÁUSULA 1ª – DO OBJETO"),
        ("Helvetica", "Implantação e suporte do sistema SecureDocs pelo prazo de 12 (doze) meses."),
        ("Helvetica", ""),
        ("Helvetica-Bold", "CLÁUSULA 2ª – DO VALOR"),
        ("Helvetica", f"O valor total deste contrato é de R$ {valor} (quarenta e oito mil e quinhentos reais),"),
        ("Helvetica", "pago em 12 parcelas mensais, iguais e sucessivas."),
        ("Helvetica", ""),
        ("Helvetica-Bold", "CLÁUSULA 3ª – DA CONFIDENCIALIDADE"),
        ("Helvetica", "As partes obrigam-se a manter sigilo sobre todas as informações trocadas."),
        ("Helvetica", ""),
        ("Helvetica-Bold", "CLÁUSULA 4ª – DO FORO"),
        ("Helvetica", "Fica eleito o foro da comarca de Goiânia – GO."),
        ("Helvetica", ""),
        ("Helvetica", "Goiânia, 26 de novembro de 2026."),
        ("Helvetica", ""), ("Helvetica", ""),
        ("Helvetica", "_____________________________            _____________________________"),
        ("Helvetica", "        CONTRATANTE                                           CONTRATADA"),
    ]
    for fonte, texto in linhas:
        c.setFont(fonte, 11)
        c.drawString(60, y, texto)
        y -= 18
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(60, 40, "Documento fictício gerado para o experimento da Missão 5 – SecureDocs.")
    c.save()


titulo("1. Geração do contrato.pdf e da versão com 1 caractere alterado")
orig = OUT / "contrato.pdf"
mod = OUT / "contrato_modificado.pdf"
gerar_contrato(orig, "48.500,00")
dados = orig.read_bytes()
alvo = b"R$ 48.500,00"
pos = dados.index(alvo) + 3                      # posição do caractere '4'
alterado = bytearray(dados)
alterado[pos] = ord("9")                         # '4' -> '9'  (R$ 98.500,00)
mod.write_bytes(bytes(alterado))
n_bytes_dif = sum(a != b for a, b in zip(dados, alterado))
n_bits_dif = sum(bin(a ^ b).count("1") for a, b in zip(dados, alterado))
print(f"Tamanho dos arquivos: {len(dados)} bytes (iguais)")
print(f"Posição alterada: byte {pos}  '4' (0x34 = {ord('4'):08b}) -> '9' (0x39 = {ord('9'):08b})")
print(f"Bytes diferentes: {n_bytes_dif} | bits diferentes na entrada: {n_bits_dif}")
R["arquivo"] = {"tamanho_bytes": len(dados), "posicao": pos, "bytes_diferentes": n_bytes_dif,
                "bits_diferentes_entrada": n_bits_dif, "de": "4", "para": "9",
                "percentual_entrada": round(100 * n_bits_dif / (len(dados) * 8), 5)}

# ---------------------------------------------------------------------------
# 2. Hash(original) x Hash(modificado) em todos os algoritmos
# ---------------------------------------------------------------------------
titulo("2. Hash(documento original) x Hash(documento modificado)")
R["comparacao"] = []
for alg in ALGS:
    t0 = time.perf_counter()
    ho = sh.hash_file(orig, alg)
    hm = sh.hash_file(mod, alg)
    dt = (time.perf_counter() - t0) / 2
    assert ho == hashlib.new(alg, dados).hexdigest()          # confere com o OpenSSL
    diff = sh.bit_difference(ho, hm)
    nb = len(ho) * 4
    R["comparacao"].append({"algoritmo": alg, "bits": nb, "hash_original": ho, "hash_modificado": hm,
                            "bits_diferentes": diff, "percentual": round(100 * diff / nb, 1),
                            "iguais": ho == hm, "tempo_ms": round(dt * 1000, 2)})
    print(f"{alg:<11}\n  original:   {ho}\n  modificado: {hm}\n  -> {diff}/{nb} bits diferentes "
          f"({100 * diff / nb:.1f}%)  {'IGUAIS' if ho == hm else 'DIFERENTES'}")

# Também com texto puro (demonstração em sala)
t1, t2 = "Valor do contrato: R$ 48.500,00", "Valor do contrato: R$ 98.500,00"
R["texto"] = {"t1": t1, "t2": t2, "linhas": []}
for alg in ["md5", "sha1", "sha256", "sha3_256"]:
    a, b = sh.new(alg, t1.encode()).hexdigest(), sh.new(alg, t2.encode()).hexdigest()
    R["texto"]["linhas"].append({"algoritmo": alg, "h1": a, "h2": b, "bits": sh.bit_difference(a, b), "total": len(a) * 4})

# ---------------------------------------------------------------------------
# 3. Efeito avalanche estatístico
# ---------------------------------------------------------------------------
titulo("3. Efeito avalanche (1000 mensagens, 1 bit invertido em cada)")
R["avalanche"] = []
for alg in ["md5", "sha1", "sha256", "sha512", "sha3_256"]:
    r = attacks.avalanche(alg, trials=1000)
    R["avalanche"].append(r)
    print(f"{alg:<9} média {r['media_bits']:6.2f}/{r['bits_saida']} bits = {r['media_pct']:.2f}%  "
          f"desvio {r['desvio']:.2f}  [min {r['min']}, max {r['max']}]")

# ---------------------------------------------------------------------------
# 4. Ataque do aniversário (colisões em hash truncado)
# ---------------------------------------------------------------------------
titulo("4. Ataque do aniversário em SHA-256 truncado")
R["aniversario"] = []
for bits in [16, 20, 24, 28, 32]:
    runs = [attacks.birthday_attack("sha256", bits, seed=s) for s in range(10)]
    media = sum(x["tentativas"] for x in runs) / len(runs)
    ex = runs[0]
    R["aniversario"].append({"bits": bits, "tentativas_media": round(media), "esperado": ex["esperado"],
                             "forca_bruta_preimagem": 2 ** bits, "exemplo": ex,
                             "tempo_medio_s": round(sum(x["tempo_s"] for x in runs) / len(runs), 2)})
    print(f"{bits} bits: média {media:,.0f} tentativas (esperado ≈ {ex['esperado']:,}) "
          f"| pré-imagem exigiria ≈ {2 ** bits:,}")
    print(f"   ex.: '{ex['msg1']}' e '{ex['msg2']}' -> {ex['hash_truncado']}")

# ---------------------------------------------------------------------------
# 5. Colisões reais: contratos envenenados (MD5 e SHA-1)
# ---------------------------------------------------------------------------
titulo("5. Colisões REAIS – mesmo hash, contratos diferentes")
texto_a = ("CONTRATO Nº 2026/0457 – Cláusula 2ª: valor total de R$ 48.500,00 "
           "(quarenta e oito mil e quinhentos reais).").encode()
texto_b = ("CONTRATO Nº 2026/0457 – Cláusula 2ª: valor total de R$ 98.500,00 "
           "(noventa e oito mil e quinhentos reais).").encode()
R["colisoes"] = {}
for nome, (p1, p2) in {"md5": attacks.load_md5_collision(), "sha1": attacks.load_sha1_collision()}.items():
    fa, fb = attacks.build_colliding_files(p1, p2, texto_a, texto_b)
    (COL / f"contrato_{nome}_A.bin").write_bytes(fa)
    (COL / f"contrato_{nome}_B.bin").write_bytes(fb)
    linhas = {}
    for alg in ["md5", "sha1", "sha256", "sha3_256"]:
        linhas[alg] = (sh.new(alg, fa).hexdigest(), sh.new(alg, fb).hexdigest())
    R["colisoes"][nome] = {
        "tamanho": len(fa), "bytes_diferentes": sum(x != y for x, y in zip(fa, fb)),
        "exibe_A": attacks.read_colliding_file(fa), "exibe_B": attacks.read_colliding_file(fb),
        "hashes": linhas,
    }
    print(f"[{nome.upper()}] arquivos de {len(fa)} bytes, {R['colisoes'][nome]['bytes_diferentes']} bytes diferentes")
    print(f"   A mostra: {attacks.read_colliding_file(fa)[:70]}...")
    print(f"   B mostra: {attacks.read_colliding_file(fb)[:70]}...")
    for alg, (x, y) in linhas.items():
        print(f"   {alg:<9} {'IGUAL    ' if x == y else 'diferente'}  {x[:32]}… / {y[:32]}…")

# ---------------------------------------------------------------------------
# 6. Ataque de extensão de comprimento
# ---------------------------------------------------------------------------
titulo("6. Ataque de extensão de comprimento (H(segredo || msg))")
segredo = b"S3cr3t0-d0-S3rv1d0r!"
msg = b"usuario=cliente42&doc=contrato.pdf&acao=ler"
ext = b"&acao=excluir"
R["extensao"] = []
for cls in [sh.MD5, sh.SHA1, sh.SHA256, sh.SHA512]:
    tag = cls(segredo + msg).hexdigest()
    forj, tag_forj = attacks.length_extension(cls, bytes.fromhex(tag), len(segredo), msg, ext)
    aceito = cls(segredo + forj).digest() == tag_forj
    R["extensao"].append({"algoritmo": cls.name, "tag_original": tag, "tag_forjada": tag_forj.hex(),
                          "mensagem_forjada": forj.hex(), "aceita_pelo_servidor": aceito,
                          "tamanho_padding": len(forj) - len(msg) - len(ext)})
    print(f"{cls.name:<7} tag forjada aceita? {aceito}")
# SHA-3 e HMAC
tag3 = sh.sha3_256(segredo + msg).digest()
tagh = sh.HMAC(segredo, msg).digest()
R["extensao_imunes"] = {"sha3_256": "imune (capacidade c=512 bits nunca é exposta)",
                        "hmac_sha256": "imune (hash externo com chave)"}
print(f"msg forjada (repr): {forj!r}")

# ---------------------------------------------------------------------------
# 7. HMAC: o atacante altera o contrato e recalcula o hash
# ---------------------------------------------------------------------------
titulo("7. Por que só o hash não basta: atacante recalcula o hash; HMAC detecta")
chave = b"chave-compartilhada-TechSecure-cliente"
h_publicado = sh.hash_file(orig, "sha256")
h_atacante = sh.hash_file(mod, "sha256")          # atacante troca arquivo E hash
hmac_orig = sh.HMAC(chave, dados).hexdigest()
hmac_mod = sh.HMAC(chave, bytes(alterado)).hexdigest()
R["hmac"] = {"sha256_original": h_publicado, "sha256_recalculado_atacante": h_atacante,
             "hmac_original": hmac_orig, "hmac_modificado": hmac_mod}
print(f"Hash enviado junto (substituído pelo atacante): {h_atacante} -> verificação PASSA (falso positivo!)")
print(f"HMAC-SHA256 recebido (original): {hmac_orig}")
print(f"HMAC-SHA256 recalculado no destino:   {hmac_mod} -> {'OK' if hmac_orig == hmac_mod else 'FALHA: alteração detectada'}")

# ---------------------------------------------------------------------------
# 8. Manifesto do repositório (documentos em repouso)
# ---------------------------------------------------------------------------
titulo("8. Manifesto de integridade do repositório SecureDocs")
repo = OUT / "repositorio_securedocs"
repo.mkdir(exist_ok=True)
(repo / "contrato.pdf").write_bytes(dados)
(repo / "relatorio_financeiro.txt").write_text("Receita 3º tri: R$ 1.250.000,00\n", encoding="utf-8")
(repo / "estrategia_2027.txt").write_text("Expansão para o Centro-Oeste.\n", encoding="utf-8")
man = sh.create_manifest(repo, chave, output=str(repo / "manifesto.json"))
antes = sh.verify_manifest(repo, repo / "manifesto.json", chave)
(repo / "contrato.pdf").write_bytes(bytes(alterado))          # adulteração no servidor
depois = sh.verify_manifest(repo, repo / "manifesto.json", chave)
(repo / "contrato.pdf").write_bytes(dados)                      # restaura
R["manifesto"] = {"manifesto": man, "antes": antes, "depois": depois}
print("Antes :", antes)
print("Depois:", depois)

# ---------------------------------------------------------------------------
# 9. Desempenho: Python puro x hashlib (C/OpenSSL)
# ---------------------------------------------------------------------------
titulo("9. Desempenho (KB/s) – Python puro x hashlib")
import os  # noqa: E402
blob = os.urandom(200_000)
R["desempenho"] = []
for alg in ["md5", "sha1", "sha256", "sha512", "sha3_256"]:
    t0 = time.perf_counter(); sh.new(alg, blob).digest(); tp = time.perf_counter() - t0
    t0 = time.perf_counter()
    for _ in range(50):
        hashlib.new(alg, blob).digest()
    tc = (time.perf_counter() - t0) / 50
    R["desempenho"].append({"algoritmo": alg, "python_kbs": round(len(blob) / 1024 / tp, 1),
                            "hashlib_kbs": round(len(blob) / 1024 / tc, 1), "fator": round(tp / tc)})
    print(f"{alg:<9} Python puro {len(blob) / 1024 / tp:9.1f} KB/s | hashlib {len(blob) / 1024 / tc:12.1f} KB/s "
          f"| {tp / tc:,.0f}x mais lento")

(OUT / "resultados.json").write_text(json.dumps(R, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
print(f"\nResultados salvos em {OUT / 'resultados.json'}")

# ---------------------------------------------------------------------------
# 10. Gráficos
# ---------------------------------------------------------------------------
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    sys.exit(0)

AZUL, LARANJA, VERDEAGUA = "#257de0", "#f47230", "#00b894"
TXT, TXT2, GRID = "#191919", "#666666", "#e6e6e6"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.edgecolor": GRID,
                     "axes.labelcolor": TXT2, "xtick.color": TXT2, "ytick.color": TXT2,
                     "axes.spines.top": False, "axes.spines.right": False})

# (a) % de bits alterados por algoritmo no experimento do contrato
fig, ax = plt.subplots(figsize=(8, 3.8), dpi=200)
nomes = [c["algoritmo"].upper().replace("_", "-") for c in R["comparacao"]]
pct = [c["percentual"] for c in R["comparacao"]]
ax.bar(nomes, pct, color=AZUL, width=0.6, edgecolor="white", linewidth=2)
ax.axhline(50, color=TXT2, linestyle="--", linewidth=1)
ax.text(-0.45, 60, "linha tracejada = ideal (50%)", color=TXT2, ha="left", fontsize=9)
for i, v in enumerate(pct):
    ax.text(i, v + 1, f"{v:.0f}%", ha="center", fontsize=8, color=TXT)
ax.set_ylim(0, 65); ax.set_ylabel("bits do hash alterados (%)")
ax.set_title(f"Trocar 1 caractere do contrato.pdf ({n_bits_dif} de {len(dados) * 8:,} bits".replace(",", ".") + ") muda ~metade do hash",
             fontsize=10.5, color=TXT, loc="left")
ax.grid(axis="y", color=GRID); ax.set_axisbelow(True)
plt.xticks(rotation=30, ha="right", fontsize=8.5)
plt.tight_layout(); plt.savefig(GRAF / "bits_alterados_contrato.png"); plt.close()

# (b) distribuição do avalanche – small multiples
fig, axs = plt.subplots(1, 5, figsize=(11, 2.8), dpi=200, sharey=False)
for ax, r in zip(axs, R["avalanche"]):
    pcts = [100 * d / r["bits_saida"] for d in r["amostras"]]
    ax.hist(pcts, bins=range(30, 71, 2), color=AZUL, edgecolor="white", linewidth=1)
    ax.axvline(50, color=LARANJA, linewidth=1.5)
    ax.set_title(f"{r['algoritmo'].upper().replace('_', '-')}\nmédia {r['media_pct']:.1f}%", fontsize=9.5, color=TXT)
    ax.set_xlim(30, 70); ax.set_xticks([40, 50, 60]); ax.set_yticks([]); ax.set_xlabel("% bits alterados", fontsize=8)
    ax.spines["left"].set_visible(False)
fig.suptitle("Efeito avalanche: 1.000 mensagens, 1 bit invertido em cada (linha laranja = 50%)",
             fontsize=10.5, color=TXT, x=0.01, ha="left")
plt.tight_layout(); plt.savefig(GRAF / "avalanche.png"); plt.close()

# (c) aniversário – tentativas observadas x esperadas x pré-imagem
fig, ax = plt.subplots(figsize=(7.5, 3.8), dpi=200)
bs = [a["bits"] for a in R["aniversario"]]
ax.plot(bs, [a["forca_bruta_preimagem"] for a in R["aniversario"]], color=LARANJA, linewidth=2,
        marker="o", markersize=7, label="pré-imagem por força bruta (2^n)")
ax.plot(bs, [a["esperado"] for a in R["aniversario"]], color=TXT2, linewidth=1.5, linestyle="--",
        label="colisão – teoria (≈1,25·2^(n/2))")
ax.plot(bs, [a["tentativas_media"] for a in R["aniversario"]], color=AZUL, linewidth=2,
        marker="o", markersize=7, label="colisão – medido nesta biblioteca")
ax.set_yscale("log"); ax.set_xticks(bs); ax.set_xlabel("bits do hash (SHA-256 truncado)")
ax.set_ylabel("tentativas (escala log)"); ax.grid(color=GRID); ax.set_axisbelow(True)
ax.legend(frameon=False, fontsize=8.5)
ax.set_title("Paradoxo do aniversário: colisão custa a raiz quadrada da força bruta", fontsize=10.5,
             color=TXT, loc="left")
plt.tight_layout(); plt.savefig(GRAF / "aniversario.png"); plt.close()

# (d) desempenho
fig, ax = plt.subplots(figsize=(7.5, 3.2), dpi=200)
dn = [d["algoritmo"].upper().replace("_", "-") for d in R["desempenho"]]
ax.barh(dn, [d["python_kbs"] for d in R["desempenho"]], color=AZUL, height=0.55)
for i, d in enumerate(R["desempenho"]):
    ax.text(d["python_kbs"] + 3, i, f"{d['python_kbs']:.0f} KB/s  (hashlib ≈ {d['fator']:,}× mais rápido)".replace(",", "."),
            va="center", fontsize=8.5, color=TXT)
ax.invert_yaxis(); ax.set_xlabel("vazão da implementação em Python puro (KB/s)")
ax.set_xlim(0, max(d["python_kbs"] for d in R["desempenho"]) * 2.1)
ax.grid(axis="x", color=GRID); ax.set_axisbelow(True)
ax.set_title("Desempenho: Python puro é didático; em produção use hashlib/OpenSSL", fontsize=10.5,
             color=TXT, loc="left")
plt.tight_layout(); plt.savefig(GRAF / "desempenho.png"); plt.close()
print("Gráficos salvos em", GRAF)
