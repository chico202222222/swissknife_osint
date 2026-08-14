import os

from playwright.sync_api import expect, sync_playwright


def main():
    base_url = os.environ.get("BASE_URL", "http://127.0.0.1:3000").rstrip("/")
    console_messages = []
    failed_requests = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900}, ignore_https_errors=True)

        page.on(
            "console",
            lambda message: console_messages.append(f"{message.type}: {message.text}")
            if message.type in {"error", "warning"}
            else None,
        )
        page.on(
            "requestfailed",
            lambda request: failed_requests.append(f"{request.method} {request.url} -> {request.failure}"),
        )

        page.goto(f"{base_url}/", wait_until="networkidle")

        privacy_guide_button = page.get_by_role("button", name="Abrir guia de privacidade")
        expect(privacy_guide_button).to_be_visible()
        expect(privacy_guide_button).to_have_attribute("data-help", "Mostra como cada ferramenta trata seus dados.")
        privacy_guide_button.hover()
        page.wait_for_timeout(200)
        assert privacy_guide_button.evaluate(
            "button => getComputedStyle(button, '::before').opacity === '1'"
        )
        expect(page.locator("#sherlock-username")).to_be_disabled()
        expect(page.locator("#nmap-target")).to_be_disabled()
        expect(page.locator("#blackbird-username")).to_be_disabled()
        expect(page.locator("#password-audit")).to_be_disabled()
        expect(page.locator("#exif-image")).to_be_disabled()
        expect(page.locator(".wireless-button")).to_have_count(2)
        expect(page.get_by_role("button", name="Inspecionar adaptadores")).to_be_disabled()
        expect(page.get_by_role("button", name="Ver VLANs")).to_be_disabled()
        expect(page.locator("#vlan-interface")).to_be_disabled()
        expect(page.locator("#vlan-id")).to_be_disabled()

        page.get_by_role("button", name="Abrir guia de privacidade").click()
        expect(page.locator("#privacy-guide")).to_be_visible()
        page.locator("#privacy-guide").get_by_role("button", name="Aceitar politica").click()

        expect(page.locator("#privacy-guide")).to_be_hidden()
        expect(page.locator("#privacy-status")).to_contain_text("Politica de privacidade aceita")
        expect(page.locator("#sherlock-username")).to_be_enabled()
        expect(page.locator("#nmap-target")).to_be_enabled()
        expect(page.locator("#blackbird-username")).to_be_enabled()
        expect(page.locator("#password-audit")).to_be_enabled()
        expect(page.locator("#exif-image")).to_be_enabled()
        expect(page.get_by_role("button", name="Inspecionar adaptadores")).to_be_enabled()
        expect(page.get_by_role("button", name="Ver VLANs")).to_be_enabled()
        expect(page.locator("#vlan-interface")).to_be_enabled()
        expect(page.locator("#vlan-id")).to_be_enabled()

        page.locator("#sherlock-username").fill("bad user!")
        expect(page.locator("#sherlock-username-validation")).to_contain_text("Os dados nao sao validos")
        page.locator("#sherlock-username").fill("octocat")
        expect(page.locator("#sherlock-username-validation")).to_contain_text("Os dados sao validos")

        page.locator("#nmap-target").fill("bad target!")
        expect(page.locator("#nmap-target-validation")).to_contain_text("Os dados nao sao validos")
        page.locator("#nmap-target").fill("127.0.0.1")
        expect(page.locator("#nmap-target-validation")).to_contain_text("Os dados sao validos")

        page.locator("#password-audit").fill("TestPass123!")
        page.get_by_role("button", name="Avaliar").click()
        expect(page.locator("#password-audit-output")).to_contain_text("Confirme a autorizacao")
        page.locator("#password-permission").check()
        page.get_by_role("button", name="Avaliar").click()
        expect(page.locator("#password-audit-output")).to_contain_text("Resiliencia: strong (5/5)")

        image_path = "osint/sherlock/docs/images/demo.png"
        page.locator("#exif-image").set_input_files(image_path)
        expect(page.locator("#exif-output")).to_contain_text("Imagem salva neste navegador")
        assert page.evaluate("Boolean(localStorage.getItem('localExifImage'))")
        page.get_by_role("button", name="Ler metadados").click()
        expect(page.locator("#exif-output")).to_contain_text("GPS: Esta imagem nao possui coordenadas GPS")
        expect(page.locator("#exif-output")).to_contain_text('"coordinates"')
        expect(page.locator("#exif-output")).to_contain_text('"available": false')
        expect(page.locator("#exif-output")).to_contain_text('"ExifToolVersion"')
        expect(page.locator("#exif-output")).to_contain_text('"ImageWidth": 920')

        page.get_by_role("button", name="Inspecionar adaptadores").click()
        expect(page.locator("#wireless-output")).to_contain_text("platform:")
        expect(page.locator("#wireless-output")).to_contain_text("tool:")
        expect(page.locator("#wireless-output")).to_contain_text("monitor_mode_supported:")

        page.get_by_role("button", name="Ver VLANs").click()
        expect(page.locator("#vlan-inventory-output")).to_contain_text("platform:")
        expect(page.locator("#vlan-inventory-output")).to_contain_text("tool:")
        expect(page.locator("#vlan-inventory-output")).to_contain_text("available:")

        page.locator("#vlan-interface").fill("en0")
        page.locator("#vlan-id").fill("5000")
        expect(page.locator("#vlan-id-validation")).to_contain_text("Os dados nao sao validos")
        page.locator("#vlan-id").fill("100")
        page.locator("#vlan-permission").check()
        page.get_by_role("button", name="Gerar plano").click()
        expect(page.locator("#vlan-output")).to_contain_text("mode: dry-run")
        expect(page.locator("#vlan-output")).to_contain_text("vlan_id: 100")

        page.get_by_role("button", name="English").click()
        expect(page.get_by_role("button", name="Open privacy guide")).to_be_visible()
        expect(page.get_by_role("button", name="Open privacy guide")).to_have_attribute(
            "data-help", "Shows how each tool handles your data."
        )
        expect(page.locator("#privacy-status")).to_contain_text("Privacy policy accepted")

        page.goto(f"{base_url}/src/index.html", wait_until="networkidle")
        expect(page.get_by_role("button", name="Abrir guia de privacidade")).to_be_visible()

        page.goto(f"{base_url}/privacy", wait_until="networkidle")
        expect(page.get_by_role("button", name="Abrir guia de privacidade")).to_be_visible()

        browser.close()

    if console_messages:
        raise AssertionError("Console warnings/errors:\n" + "\n".join(console_messages))
    if failed_requests:
        raise AssertionError("Failed requests:\n" + "\n".join(failed_requests))

    print("webapp smoke test passed")


if __name__ == "__main__":
    main()
