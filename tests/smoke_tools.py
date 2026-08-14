from playwright.sync_api import expect, sync_playwright


def main():
    console_messages = []
    failed_requests = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 1100})
        page.set_default_timeout(150_000)

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

        page.goto("http://127.0.0.1:3000/", wait_until="networkidle")
        page.get_by_role("button", name="Aceitar politica").click()

        page.locator("#sherlock-username").fill("octocat")
        page.locator("#sherlock-username").locator("xpath=following-sibling::button").click()
        expect(page.locator("#sherlock-output")).to_contain_text("Search completed", timeout=150_000)
        expect(page.locator("#sherlock-output")).to_contain_text("GitHub", timeout=150_000)

        page.locator("#blackbird-username").fill("octocat")
        page.locator("#blackbird-username").locator("xpath=following-sibling::button").click()
        expect(page.locator("#blackbird-output")).to_contain_text("Check completed", timeout=150_000)
        expect(page.locator("#blackbird-output")).to_contain_text("GitHub", timeout=150_000)

        page.locator("#nmap-target").fill("127.0.0.1")
        page.locator("#security-permission").check()
        page.get_by_role("button", name="Analisar").click()
        expect(page.locator("#nmap-output")).to_contain_text("Nmap done", timeout=150_000)
        expect(page.locator("#nmap-output")).to_contain_text("8000/tcp", timeout=150_000)

        page.locator("#password-audit").fill("TestPass123!")
        page.locator("#password-permission").check()
        page.get_by_role("button", name="Avaliar").click()
        expect(page.locator("#password-audit-output")).to_contain_text("Resiliencia: strong (5/5)")

        browser.close()

    if console_messages:
        raise AssertionError("Console warnings/errors:\n" + "\n".join(console_messages))
    if failed_requests:
        raise AssertionError("Failed requests:\n" + "\n".join(failed_requests))

    print("all tool UI smoke tests passed")


if __name__ == "__main__":
    main()
