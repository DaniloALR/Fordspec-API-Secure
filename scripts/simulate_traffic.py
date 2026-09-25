"""Gera tráfego legítimo e ataques simulados para popular dashboards e alertas.

Use SOMENTE contra o seu ambiente local (docker compose).

  python -m scripts.simulate_traffic --url http://localhost:8000 --ciclos 3
Credenciais: SIM_USER / SIM_PASSWORD (um usuário brigadista válido).
"""
import argparse
import os
import time

import httpx

VERSAO = "Limited 3.0L V6 26MY"


def _login(c: httpx.Client, user: str, senha: str) -> dict:
    r = c.post("/v1/auth/login", json={"username": user, "password": senha})
    r.raise_for_status()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def trafego_legitimo(c, h):
    c.get("/v1/attributes", headers=h)
    c.get("/v1/vehicles", params={"brand": "Ford", "model": "Ranger"}, headers=h)
    c.post("/v1/specs", headers=h, json={"brand": "Ford", "model": "Ranger",
                                         "version": VERSAO, "attributes": ["Potência"]})


def ataque_brute_force(c):
    for i in range(8):
        c.post("/v1/auth/login", json={"username": "gestor", "password": f"chute-{i:04d}"})


def ataque_injecao(c, h):
    for payload in ["' OR 1=1 --", "<script>alert(1)</script>", "x; DROP TABLE spec_value"]:
        c.post("/v1/specs", headers=h, json={"brand": "Ford", "model": "Ranger",
                                             "version": payload})


def ataque_escalonamento(c, h):
    c.get("/v1/admin/users", headers=h)
    c.get("/v1/specs/export", params={"version": VERSAO}, headers=h)
    c.get("/v1/specs/00000000-0000-0000-0000-000000000000", headers=h)


def ataque_token_forjado(c):
    forjado = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
               "eyJzdWIiOiJhZG1pbmlzdHJhZG9yIiwicm9sZSI6ImFkbWluaXN0cmFkb3IifQ.")
    c.get("/v1/auth/me", headers={"Authorization": f"Bearer {forjado}"})


def ataque_flood(c, h):
    for _ in range(70):
        c.get("/", headers=h)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://localhost:8000")
    p.add_argument("--ciclos", type=int, default=3)
    a = p.parse_args()
    user, senha = os.environ["SIM_USER"], os.environ["SIM_PASSWORD"]
    with httpx.Client(base_url=a.url, timeout=10) as c:
        h = _login(c, user, senha)
        for ciclo in range(a.ciclos):
            for _ in range(10):
                trafego_legitimo(c, h)
            ataque_injecao(c, h)
            ataque_escalonamento(c, h)
            ataque_token_forjado(c)
            ataque_brute_force(c)
            ataque_flood(c, h)
            print(f"[simulação] ciclo {ciclo + 1}/{a.ciclos} concluído")
            time.sleep(61)  # janela do rate limit


if __name__ == "__main__":
    main()
