"""Testes funcionais do contrato REST (regra ND, erros padronizados, exportação)."""
from tests.conftest import VERSAO


def test_health(client):
    assert client.get("/").json()["status"] == "ok"


def test_dicionario_de_atributos(client, headers):
    attrs = client.get("/v1/attributes", headers=headers["brigadista"]).json()
    assert len(attrs) == 262
    assert len({a["category"] for a in attrs}) == 14


def test_versoes_da_base_curada(client, headers):
    versoes = client.get("/v1/vehicles?brand=Ford&model=Ranger",
                         headers=headers["brigadista"]).json()
    assert {"brand": "Ford", "model": "Ranger", "version": VERSAO} in versoes


def test_gera_ficha_padronizada(client, headers):
    r = client.post("/v1/specs", headers=headers["brigadista"], json={
        "brand": "Ford", "model": "Ranger", "version": VERSAO,
        "attributes": ["Potência", "Torque"]})
    assert r.status_code == 201
    corpo = r.json()
    assert corpo["total_attributes"] == 2
    assert {i["attribute"] for i in corpo["items"]} == {"Potência", "Torque"}
    for item in corpo["items"]:
        assert item["status"] in ("confirmed", "not_available")
        if item["status"] == "not_available":
            assert item["value"] == "ND"


def test_versao_inexistente_422(client, headers):
    r = client.post("/v1/specs", headers=headers["brigadista"], json={
        "brand": "Ford", "model": "Ranger", "version": "Raptr"})
    assert r.status_code == 422
    assert r.json()["error"] == "version_not_found"


def test_atributo_fora_do_dicionario_400(client, headers):
    r = client.post("/v1/specs", headers=headers["brigadista"], json={
        "brand": "Ford", "model": "Ranger", "version": VERSAO, "attributes": ["Cor do banco"]})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_attribute"


def test_exporta_csv(client, headers):
    r = client.get(f"/v1/specs/export?version={VERSAO}", headers=headers["gestor"])
    assert r.status_code == 200
    assert r.text.splitlines()[0] == "Categoria;Atributo;Valor;Status"
    assert 'filename="ficha_Ford_Ranger_Limited_3.0L_V6_26MY.csv"' in \
        r.headers["content-disposition"]
