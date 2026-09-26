import argparse
import functools
import hashlib
import os
import sqlite3
import subprocess  # nosec B404
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import _secret, settings
from app.db.database import DATABASE_URL
from app.security.data_privacy import construir_cifrador

BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "backups"))
RETENCAO = int(os.getenv("BACKUP_RETENTION", "14"))


@functools.lru_cache(maxsize=1)
def _cifrador():
    return construir_cifrador([_secret("BACKUP_ENC_KEY", settings.is_production)])


def _caminho_sqlite(url: str) -> str:
    return url.split("sqlite:///", 1)[1]


def _dump_bruto(url: str) -> bytes:
    if url.startswith("sqlite"):
        with tempfile.TemporaryDirectory() as tmp:
            destino = os.path.join(tmp, "snap.db")
            with sqlite3.connect(_caminho_sqlite(url)) as origem, \
                    sqlite3.connect(destino) as copia:
                origem.backup(copia)
            copia.close()
            return Path(destino).read_bytes()
    if url.startswith("postgresql"):
        pg_url = url.replace("postgresql+psycopg2://", "postgresql://")
        return subprocess.run(["pg_dump", "-Fc", "--dbname", pg_url],  # nosec B603 B607
                              check=True, capture_output=True).stdout
    raise SystemExit(f"Banco não suportado para backup: {url.split(':')[0]}")


def backup(url: str = DATABASE_URL, pasta: Path = BACKUP_DIR) -> Path:
    pasta.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    arquivo = pasta / f"fordspec-{ts}.db.enc"
    cifrado = _cifrador().encrypt(_dump_bruto(url))
    arquivo.write_bytes(cifrado)
    Path(f"{arquivo}.sha256").write_text(hashlib.sha256(cifrado).hexdigest(), encoding="utf-8")
    _aplicar_retencao(pasta)
    print(f"[backup] OK {arquivo} ({len(cifrado)} bytes cifrados)")
    return arquivo


def _aplicar_retencao(pasta: Path):
    antigos = sorted(pasta.glob("fordspec-*.db.enc"))[:-RETENCAO]
    for a in antigos:
        a.unlink()
        Path(f"{a}.sha256").unlink(missing_ok=True)
        print(f"[backup] retenção: removido {a.name}")


def _decifrar(arquivo: Path) -> bytes:
    cifrado = arquivo.read_bytes()
    manifesto = Path(f"{arquivo}.sha256")
    if manifesto.exists() and manifesto.read_text().strip() != hashlib.sha256(cifrado).hexdigest():
        raise SystemExit("[backup] FALHA: hash não confere (arquivo corrompido/adulterado).")
    return _cifrador().decrypt(cifrado)


def _integridade_sqlite(caminho: str) -> bool:
    with sqlite3.connect(caminho) as conn:
        ok = conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        tabelas = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    return ok and {"attribute", "vehicle_version", "app_user"} <= tabelas


def verify(arquivo: Path) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        destino = os.path.join(tmp, "restore.db")
        Path(destino).write_bytes(_decifrar(arquivo))
        ok = _integridade_sqlite(destino)
    print(f"[backup] verificação de {arquivo.name}: {'OK' if ok else 'FALHOU'}")
    return ok


def restore(arquivo: Path, destino: Path):
    if destino.exists():
        destino.rename(destino.with_suffix(destino.suffix + ".pre-restore"))
    destino.write_bytes(_decifrar(arquivo))
    if not _integridade_sqlite(str(destino)):
        raise SystemExit("[backup] restauração com falha de integridade.")
    print(f"[backup] restaurado em {destino}")


def main():
    p = argparse.ArgumentParser(description="Backup cifrado do banco FordSpec")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("backup")
    v = sub.add_parser("verify")
    v.add_argument("arquivo", type=Path)
    r = sub.add_parser("restore")
    r.add_argument("arquivo", type=Path)
    r.add_argument("destino", type=Path)
    a = p.parse_args()
    if a.cmd == "backup":
        backup()
    elif a.cmd == "verify":
        sys.exit(0 if verify(a.arquivo) else 1)
    else:
        restore(a.arquivo, a.destino)


if __name__ == "__main__":
    main()
