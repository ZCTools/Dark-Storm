import dns.resolver
import requests

def get_dns_records(domain):
    records = {}
    try:
        records['A'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'A')]
    except dns.resolver.NoAnswer:
        records['A'] = []

    try:
        records['AAAA'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'AAAA')]
    except dns.resolver.NoAnswer:
        records['AAAA'] = []

    try:
        records['MX'] = [str(rdata.exchange) for rdata in dns.resolver.resolve(domain, 'MX')]
    except dns.resolver.NoAnswer:
        records['MX'] = []

    try:
        records['NS'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'NS')]
    except dns.resolver.NoAnswer:
        records['NS'] = []

    try:
        records['TXT'] = [str(rdata) for rdata in dns.resolver.resolve(domain, 'TXT')]
    except dns.resolver.NoAnswer:
        records['TXT'] = []

    return records

def find_subdomains(domain, wordlist):
    subdomains = []
    for word in wordlist:
        subdomain = f"{word}.{domain}"
        try:
            dns.resolver.resolve(subdomain, 'A')
            subdomains.append(subdomain)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
    return subdomains

def main():
    domain = input("Bir Domain Giriniz: ")
    
    # DNS records
    print(f"DNS Kayıtları Yakalanıyor {domain}...")
    records = get_dns_records(domain)
    for record_type, rdata in records.items():
        print(f"{record_type}[+] Kayıtlar:")
        for entry in rdata:
            print(f"  {entry}")
    
    # Subdomain enumeration
    wordlist = ['www', 'mail', 'ftp', 'test', 'dev']  # örnek kelime listesi
    print(f"\n[+] Subdomain'ler Bulundu {domain}...")
    subdomains = find_subdomains(domain, wordlist)
    if subdomains:
        print("Bulunan Subdomain'ler:")
        for subdomain in subdomains:
            print(f"  {subdomain}")
    else:
        print("[-] Subdomain'ler Bulunamadı.")

if __name__ == "__main__":
    main()
