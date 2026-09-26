import pytest

from app.db.database import DATABASE_URL
from scripts import backup_db


def test_backup_cifrado_e_restauravel(tmp_path):
    arquivo = backup_db.backup(DATABASE_URL, tmp_path)
    conteudo = arquivo.read_bytes()
    assert b"SQLite format" not in conteudo and b"app_user" not in conteudo
    assert backup_db.verify(arquivo) is True
    destino = tmp_path / "restaurado.db"
    backup_db.restore(arquivo, destino)
    assert destino.exists()


def test_backup_adulterado_detectado(tmp_path):
    arquivo = backup_db.backup(DATABASE_URL, tmp_path)
    dados = bytearray(arquivo.read_bytes())
    dados[100] ^= 0xFF
    arquivo.write_bytes(bytes(dados))
    with pytest.raises(SystemExit):
        backup_db.verify(arquivo)


def test_retencao(tmp_path, monkeypatch):
    monkeypatch.setattr(backup_db, "RETENCAO", 2)
    for _ in range(4):
        backup_db.backup(DATABASE_URL, tmp_path)
    assert len(list(tmp_path.glob("*.db.enc"))) == 2
