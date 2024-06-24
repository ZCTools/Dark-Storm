import os
import sys

def check_root():
    if os.geteuid() == 0:
        print("[+] Cihaza Root yetkisi verildi")
        return True
    else:
        print("[-] ER0R: Cihazınıza Root yetkisi verdiniz mi?")
        return False

if __name__ == "__main__":
    if not check_root():
        sys.exit("[?] Çıkılıyor. Cihazınza Root yetkisi verip tekrar deneyin.")
