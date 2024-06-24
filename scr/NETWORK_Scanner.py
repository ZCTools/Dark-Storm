from scapy.all import ARP, Ether, srp
import socket

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
