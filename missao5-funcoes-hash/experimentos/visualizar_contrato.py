"""
"Visualizador" dos contratos envenenados gerados pelo experimento (demonstração ao vivo).

    python experimentos/visualizar_contrato.py experimentos/saida/colisoes/contrato_md5_A.bin \
                                                experimentos/saida/colisoes/contrato_md5_B.bin

Mostra o conteúdo exibido por cada arquivo e seus hashes MD5, SHA-1, SHA-256 e SHA3-256.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import securedocs_hash as sh                      # noqa: E402
from securedocs_hash.attacks import read_colliding_file  # noqa: E402

for caminho in sys.argv[1:]:
    dados = Path(caminho).read_bytes()
    print(f"\n=== {caminho} ({len(dados)} bytes) ===")
    print("Conteúdo exibido:", read_colliding_file(dados))
    for alg in ["md5", "sha1", "sha256", "sha3_256"]:
        print(f"  {alg:<9} {sh.new(alg, dados).hexdigest()}")
