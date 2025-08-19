import argparse
import json
import re
import sys
import os
from urllib.parse import urlparse
from typing import Dict, List
from pprint import pprint
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress
import time


class JavascriptResource:
    def __init__(self, referer_url: str, js_domain: str, resource_url: str, disposition: str = None):
        self.referer_url = referer_url  # The URL where the resource was requested from
        self.js_domain = js_domain  # The domain of the JavaScript resource
        self.resource_url = resource_url  # The full URL of the JavaScript resource
        self.disposition = disposition  # "internal" or "external"

    def to_dict(self):
        """Convert the object to a dictionary for JSON serialization."""
        return {
            "referer_url": self.referer_url,
            "js_domain": self.js_domain,
            "resource_url": self.resource_url,
            "disposition": self.disposition,
        }


def load_site(url: str) -> list:
    """Load the given URL in a headless Chrome browser and return performance logs."""
    caps = DesiredCapabilities.CHROME.copy()
    caps["goog:loggingPrefs"] = {"performance": "ALL"}

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--single-process")
    options.add_argument("--disable-accelerated-2d-canvas")
    options.add_argument("--no-first-run")
    options.add_argument("--disable-renderer-backgrounding")
    options.add_argument("--memory-pressure-off")  


    for key, value in caps.items():
        options.set_capability(key, value)

    start_time = time.time()
    driver = webdriver.Chrome(options=options)
    chrome_start_time = time.time()
    print(f"Chrome startup time: {chrome_start_time - start_time:.2f} seconds")

    driver.set_page_load_timeout(60)  # Set timeout for page loading

    try:
        driver.get(url)
        return driver.get_log("performance")
    
    except TimeoutException:
        print(f"Timeout while trying to load the page: {url}")
        return []
    except Exception as e:
        print(f"An error occurred while loading the page: {e}")
        return []
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


def extract_script_domains(current_domain: str, logs: List[dict]) -> List['JavascriptResource']:
    """Extract JavaScript resources from logs and return a list of JavascriptResource objects."""
    resources = []

    for entry in logs:
        message = json.loads(entry["message"]).get("message", {})
        if message.get("method") == "Network.responseReceived":
            params = message.get("params", {})
            if params.get("type") == "Script":
                url = params.get("response", {}).get("url")
                if url and len(urlparse(url).netloc) > 0:
                    js_domain = urlparse(url).netloc
                    resources.append(JavascriptResource(
                        referer_url=current_domain,
                        js_domain=js_domain,
                        resource_url=url
                    ))
    return resources

def classify(resources: List['JavascriptResource'], site_domain: str, internal_domains: set) -> None:
    """Classify JavaScript resources as internal or external."""
    for resource in resources:
        if resource.js_domain == site_domain or resource.js_domain in internal_domains:
            resource.disposition = "internal"
        else:
            resource.disposition = "external"

def _classify(current_domain: str, domains: set, site_domain: str, internal_domains: set) -> List[Dict[str, str]]:
    """Classify domains as internal or external relative to the site domain or provided internal domains."""
    results = []
    
    for domain in domains:
        if domain == site_domain or domain in internal_domains:
            tag = "internal"
        else:
            tag = "external"
        results.append({"target_url": current_domain, "js_domain": domain, "tag": tag})
    return results

def is_valid_url(url: str) -> bool:
    URL_REGEX = re.compile(r'^(https?://)[\w.-]+(?:\.[\w\.-]+)+[/#?]?.*$')
    return bool(URL_REGEX.match(url))

def write_results_to_json(resources: List['JavascriptResource'], output_file: str) -> None:
    """Write the results to a JSON file."""
    print(f"Found {len(resources)} results. Writing results to {output_file}")
    with open(output_file, "w") as f:
        json.dump([resource.to_dict() for resource in resources], f, indent=4)

def write_summary_to_json(resources: List['JavascriptResource'], summary_file: str) -> None:
    """Write a summary JSON file with internal and external JS domains grouped by referer_url."""
    summary = {}

    for resource in resources:
        if resource.referer_url not in summary:
            summary[resource.referer_url] = {"internal": [], "external": []}

        if resource.disposition == "internal":
            summary[resource.referer_url]["internal"].append(resource.js_domain)
        elif resource.disposition == "external":
            summary[resource.referer_url]["external"].append(resource.js_domain)

    # Remove duplicates in the lists
    for referer_url, domains in summary.items():
        domains["internal"] = list(set(domains["internal"]))
        domains["external"] = list(set(domains["external"]))

    print(f"Writing summary to {summary_file}")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=4)

def load_internal_domains(domains_file: str) -> set:
    """Load internal domains from a file."""
    if not os.path.exists(domains_file):
        raise FileNotFoundError(f"Domains file {domains_file} does not exist.")

    with open(domains_file, "r") as f:
        internal_domains = {line.strip() for line in f if line.strip()}
    print(f"Loaded {len(internal_domains)} internal domains from {domains_file}")
    return internal_domains

def process_domains_in_parallel(domains: List[str], internal_domains: set, max_workers: int) -> List[JavascriptResource]:
    """Process domains in parallel using a ThreadPoolExecutor."""
    resources = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(process_single_domain, domain, internal_domains): domain for domain in domains}

        with Progress() as progress:
            task = progress.add_task("Scanning domains...", total=len(domains))

            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    resources.extend(result)
                except Exception as e:
                    print(f"Error processing domain {domain}: {e}")
                finally:
                    progress.update(task, advance=1)

    return resources

def process_single_domain(domain: str, internal_domains: set) -> List[JavascriptResource]:
    """Process a single domain."""
    if not is_valid_url(domain):
        raise ValueError(f"Invalid URL: {domain}")

    site_domain = urlparse(domain).netloc
    logs = load_site(domain)
    resources = extract_script_domains(domain, logs)
    classify(resources, site_domain, internal_domains)
    return resources

def process_input_file(input_file: str, internal_domains: set, max_workers: int) -> List[JavascriptResource]:
    """Process domains from an input file in parallel."""
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file {input_file} does not exist.")

    with open(input_file, "r") as f:
        domains_to_scan = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(domains_to_scan)} domains to be sanned from {input_file}")
    return process_domains_in_parallel(domains_to_scan, internal_domains, max_workers)

def main() -> None:
    parser = argparse.ArgumentParser(description="Extract resource domains from a web page.")

    parser.add_argument("url", nargs="?", help="URL of the site to scan")
    parser.add_argument("-i", "--input-file", help="Path to a file containing domains to scan", type=str)
    parser.add_argument("-d", "--domains-file", help="Path to a file containing internal domains", type=str)
    parser.add_argument("-o", "--output-file", help="Path to a file to save results in JSON format", type=str)
    parser.add_argument("-j", "--jobs", help="Number of parallel jobs", type=int, default=2)

    args = parser.parse_args()
    resources = []

    if not args.url and not args.input_file:
        parser.error("Either a URL or an input file must be provided.")

    internal_domains = set()
    if args.domains_file:
        internal_domains = load_internal_domains(args.domains_file)

    if args.input_file:
        resources.extend(process_input_file(args.input_file, internal_domains, args.jobs))

    if args.url:
        resources.extend(process_domains_in_parallel([args.url], internal_domains, args.jobs))

    if args.output_file:
        write_results_to_json(resources, args.output_file)
        summary_file = os.path.splitext(args.output_file)[0] + "_summary.txt"
        write_summary_to_json(resources, summary_file)
    else:
        print("Javascript Domains Loaded:")
        print(tabulate([resource.to_dict() for resource in resources], headers="keys", tablefmt="github"))

if __name__ == "__main__":
    main()
