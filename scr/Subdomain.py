import requests

def find_subdomains(domain, wordlist):
    found_subdomains = []
    for word in wordlist:
        subdomain = f"http://{word}.{domain}"
        try:
            response = requests.get(subdomain)
            if response.status_code == 200:
                print(f"Found: {subdomain}")
                found_subdomains.append(subdomain)
        except requests.ConnectionError:
            pass
    return found_subdomains

def main():
    domain = input("Taranacak bir Domain Giriniz: (e.g., örnek.com): ")
    # Örnek kelime listesi
    wordlist = ['www', 'mail', 'ftp', 'test', 'dev']

    found_subdomains = find_subdomains(domain, wordlist)
    if found_subdomains:
        print("\n[+] Sobdomain'ler Bulundu:")
        for subdomain in found_subdomains:
            print(subdomain)
    else:
        print("[-] Sobdomain'ler Bulunamadı.")

if __name__ == "__main__":
    main()
