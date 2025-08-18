import argparse
import json
from urllib.parse import urlparse
from typing import Dict, List

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities


def load_site(url: str) -> list:
    """Load the given URL in a headless Chrome browser and return performance logs."""
    caps = DesiredCapabilities.CHROME.copy()
    caps["goog:loggingPrefs"] = {"performance": "ALL"}

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    for key, value in caps.items():
        options.set_capability(key, value)

    driver = webdriver.Chrome(options=options)
    try:
        driver.get(url)
        return driver.get_log("performance")
    finally:
        driver.quit()


def extract_resource_domains(logs: List[dict], site_domain: str) -> List[Dict[str, str]]:
    """Return unique domains for all requested resources."""
    domains = set()
    for entry in logs:
        message = json.loads(entry["message"]).get("message", {})
        if message.get("method") == "Network.requestWillBeSent":
            url = message.get("params", {}).get("request", {}).get("url")
            if url:
                domains.add(urlparse(url).netloc)
    return _classify(domains, site_domain)


def extract_script_domains(logs: List[dict], site_domain: str) -> List[Dict[str, str]]:
    """Return unique domains for JavaScript resources."""
    domains = set()
    for entry in logs:
        message = json.loads(entry["message"]).get("message", {})
        if message.get("method") == "Network.responseReceived":
            params = message.get("params", {})
            if params.get("type") == "Script":
                url = params.get("response", {}).get("url")
                if url:
                    domains.add(urlparse(url).netloc)
    return _classify(domains, site_domain)


def _classify(domains: set, site_domain: str) -> List[Dict[str, str]]:
    """Classify domains as internal or external relative to the site domain."""
    results = []
    for domain in sorted(domains):
        tag = "external" if domain != site_domain else "internal"
        results.append({"domain": domain, "tag": tag})
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract resource domains from a web page.")
    parser.add_argument("url", help="URL of the site to scan")
    args = parser.parse_args()

    site_domain = urlparse(args.url).netloc
    logs = load_site(args.url)

    all_domains = extract_resource_domains(logs, site_domain)
    script_domains = extract_script_domains(logs, site_domain)

    print("All resource domains:")
    for info in all_domains:
        print(f"- {info['domain']} ({info['tag']})")
    print("\nJavaScript domains:")
    for info in script_domains:
        print(f"- {info['domain']} ({info['tag']})")


if __name__ == "__main__":
    main()
