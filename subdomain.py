import re
import socket
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import tldextract

def resolve_hostname(target):
    """
    Resolves the hostname and validates the target.
    Returns (hostname, error_message) tuple.
    """
    if not target:
        return None, 'Target name is required!'

    if re.search(r'.+\.(com|gov|org|edu|net|co)$', target):
        hostname = target
        return hostname, None
    elif re.search(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}+\.[0-9]{1,3}+$', target):
        ipaddress = target
        try:
            hostname = socket.gethostbyaddr(ipaddress)[0]
            return hostname, None
        except socket.herror:
            return None, 'Unable to resolve IP address!'
    else:
        return None, 'Invalid target format!'

def find_subdomains_and_crawl(target, max_visits=100):
    """
    Handles target validation, tries HTTPS first then HTTP, and crawls for subdomains.
    Returns (subdomains_list, error_message) tuple.
    """
    hostname, error = resolve_hostname(target)
    if error:
        return [], error

    discovered_subdomains = []
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{hostname}"
            subdomains = _crawl_for_subdomains(url, max_visits)
            if subdomains:
                discovered_subdomains = subdomains
                break
        except Exception:
            continue

    if not discovered_subdomains:
        return [], "No subdomains found."
    return discovered_subdomains, None

def _crawl_for_subdomains(base_url, max_visits=100):
    """
    Crawls a website to find subdomains mentioned in internal links.
    Uses tldextract for robust domain parsing and adds a User-Agent header.
    Limits crawl to max_visits pages.
    Returns a list of discovered subdomains.
    """
    urls_to_visit = [base_url]
    visited_urls = set()
    found_subdomains = set()

    base_extract = tldextract.extract(base_url)
    base_registered_domain = f"{base_extract.domain}.{base_extract.suffix}"

    headers = {'User-Agent': 'Mozilla/5.0 (compatible; SubdomainCrawler/1.0)'}

    while urls_to_visit and len(visited_urls) < max_visits:
        url = urls_to_visit.pop(0)
        if url in visited_urls:
            continue
        visited_urls.add(url)

        try:
            response = requests.get(url, headers=headers, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                full_link = urljoin(url, link['href'])
                parsed_link = urlparse(full_link)
                if not parsed_link.hostname:
                    continue

                link_extract = tldextract.extract(parsed_link.hostname)
                link_registered_domain = f"{link_extract.domain}.{link_extract.suffix}"

                # Check if link is to a subdomain of the base domain
                if link_registered_domain == base_registered_domain:
                    if link_extract.subdomain and parsed_link.hostname != urlparse(base_url).hostname:
                        found_subdomains.add(parsed_link.hostname)
                    if full_link not in visited_urls and full_link not in urls_to_visit:
                        urls_to_visit.append(full_link)

        except requests.exceptions.RequestException:
            continue

    return list(found_subdomains)

# Example usage for testing (remove or comment out when importing in app.py)
if __name__ == "__main__":
    target_url = "hackerai.co"
    subdomains, error = find_subdomains_and_crawl(target_url)
    if error:
        print(f"Error: {error}")
    else:
        print(f"Discovered subdomains: {subdomains}")
