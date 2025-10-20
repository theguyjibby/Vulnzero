import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# TODO: Enhance to crawl discovered directories for deeper enumeration if needed

def get_subdirectories(hostname, path='/', max_scheme_attempts=2):
    """
    Fetches and lists immediate subdirectories from a website's directory listing.
    Takes just the hostname (e.g., 'example.com') and tries https, then http.
    Optionally, you can specify a path (default is '/').
    """
    subdirs = []
    error = None
    schemes = ['https', 'http']
    for scheme in schemes[:max_scheme_attempts]:
        url = f"{scheme}://{hostname}{path if path.startswith('/') else '/' + path}"
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; SubdirectoryFinder/1.0)'}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and href.endswith('/') and not href.startswith('..') and href != '/':
                    full_url = urljoin(url, href)
                    subdirs.append(full_url)
            if subdirs:
                return subdirs, None
        except requests.exceptions.RequestException as e:
            error = f"Error accessing {url}: {e}"
            continue
    return subdirs, error

# Example usage:
if __name__ == "__main__":
    hostname = "example.com"  # Just the hostname
    path = "/some/directory/" # Optional: directory path, or just "/" for root
    subdirectories, error = get_subdirectories(hostname, path)
    if error:
        print(error)
    elif subdirectories:
        print(f"Subdirectories of https://{hostname}{path}:")
        for subdir in subdirectories:
            print(subdir)
    else:
        print("Could not find any subdirectories or website access failed.")
