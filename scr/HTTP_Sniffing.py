from scapy.all import sniff, Raw, IP
import re

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
