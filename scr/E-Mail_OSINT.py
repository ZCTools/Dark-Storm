import re
import requests
from bs4 import BeautifulSoup

def find_emails(starting_text, url):
    try:
        response = requests.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[-] ER0R: URL Yakalanırken Bir Sorun Oluştu {e}")
        return []

    page_content = response.text
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', page_content)
    filtered_emails = [email for email in emails if email.startswith(starting_text)]
    return filtered_emails

def main():
    starting_text = input("Email'ler için bir Başlangıç Metni Giriniz: ")
    url = input("Taranacak URL'yi Giriniz: ")
    emails = find_emails(starting_text, url)
    if emails:
        print("[+] Email'ler Bulundu:")
        for email in emails:
            print(email)
    else:
        print("[-] Verilen Metinle Başlayan Email Bulunamadı.")

if __name__ == "__main__":
    main()


