"""Captura prints de Grafana e Prometheus do ambiente docker compose (workflow de evidências)."""
import os
import sys
import time

from playwright.sync_api import sync_playwright

SAIDA = sys.argv[1] if len(sys.argv) > 1 else "prints"
GRAFANA = "http://localhost:3000"
PROMETHEUS = "http://localhost:9090"
SENHA = os.environ["GF_SECURITY_ADMIN_PASSWORD"]
os.makedirs(SAIDA, exist_ok=True)


def print_(page, nome, url, espera=8, altura=None):
    page.goto(url, wait_until="networkidle", timeout=60_000)
    time.sleep(espera)
    if altura:
        page.set_viewport_size({"width": 1600, "height": altura})
        time.sleep(2)
    page.screenshot(path=os.path.join(SAIDA, nome), full_page=True)
    print("capturado", nome)


with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1600, "height": 1000})

    page.goto(f"{GRAFANA}/login", wait_until="networkidle")
    page.fill("input[name='user']", "admin")
    page.fill("input[name='password']", SENHA)
    page.click("button[type='submit']")
    page.wait_for_load_state("networkidle")
    time.sleep(3)
    if "/login" in page.url:
        # primeira entrada pode pedir troca de senha: "Skip"
        try:
            page.click("text=Skip", timeout=5_000)
        except Exception:
            pass

    painel = f"{GRAFANA}/d/fordspec-security/?orgId=1&from=now-20m&to=now&kiosk"
    print_(page, "01_grafana_dashboard_seguranca.png", painel, espera=15, altura=2400)

    print_(page, "02_prometheus_alertas.png", f"{PROMETHEUS}/alerts?state=firing", espera=5)
    print_(page, "03_prometheus_targets.png", f"{PROMETHEUS}/targets", espera=5)

    loki = (f"{GRAFANA}/explore?orgId=1&left=%7B%22datasource%22:%22loki%22,%22queries%22:"
            "%5B%7B%22refId%22:%22A%22,%22expr%22:%22%7Bjob%3D%5C%22fordspec-api%5C%22,"
            "%20tipo%3D~%5C%22seguranca%7Cauditoria%5C%22%7D%20!%3D%20%5C%22rate_limit_excedido%5C%22%22%7D%5D,%22range%22:%7B%22from%22:"
            "%22now-20m%22,%22to%22:%22now%22%7D%7D")
    print_(page, "04_loki_logs_seguranca.png", loki, espera=10)
    browser.close()
