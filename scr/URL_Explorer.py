import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def get_links(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] ER0R: URL Yakalanırken/Alınırken Sorun OLuştu.{e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')
    links = set()
    for tag in soup.find_all('a', href=True):
        href = tag.get('href')
        full_url = urljoin(url, href)
        if full_url.startswith(url):  # Only follow links within the same domain
            links.add(full_url)
    return links

def main():
    start_url = input("[?] Taranacak URL'yi Giriniz (e.g., http://örnek.com): ")
    parsed_url = urlparse(start_url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    scanned_urls = set()
    to_scan = {start_url}

    while to_scan:
        current_url = to_scan.pop()
        if current_url in scanned_urls:
            continue

        print(f"[*] Taranıyor: {current_url}")
        links = get_links(current_url)
        to_scan.update(links - scanned_urls)
        scanned_urls.add(current_url)

        # Print found URLs as they are discovered
        for link in links:
            print(f"[+] Bulunan Linkler: {link}")

    print("\n[+] Bulunan Tüm Linkler:")
    for found_url in scanned_urls:
        print(found_url)

if __name__ == "__main__":
    main()
