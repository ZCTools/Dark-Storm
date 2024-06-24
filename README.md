# Dark-Storm:
Dark-Storm, bir kaç saldırıyı bir araya toplayıp, tek tek çalıştırabileceğiniz bir Framework'tür.
Özellikleri şunlardır:
1) DoS Saldırısı bulundurur.
2) Kali Linux'taki "netdiscover" komutu gibi bir ağ analiz kodu vardır
ve ağda bulunan cihazları şu şekilde listeler:
----------------------------------------------
Cihaz-1:
Ad: Ağda bulunan bir cihazın adı
IP Adresi: Ağda bulunan cihazın IP Adresi
MAC Adresi: Ağda bulunan cihazın MAC Adresi
-----------------------------------------------
3) WEB OINT yapmanızı sağlayacak bazı kodlar vardır:
Belirtilen URL'de XSS ve SQL Injection Zafiyet tarayıcısı,
URL'de subdomain bulucu
Girilen URL'de bir metinle ilgili Email bulucu
ve DNS Dumpster
4) HTTP/S Sniffing kodu vardır.
5) Keylogger kodu bulundurur
6) Windows için tehlikeli bazı .bat dosyları vardır.

Çalşıtırmak için:
1) git clone https://github.com/ZCTools/Dark-Storm
2) cd Dark-Storm
3) pip3 install -r requirements.txt
4) python3 tool.py
Kodun içinde çok fazla kütüphane olduğuna bakmayın bunların sadece 5 ya da 4 tanesi
pip3 install komutu ile yüklenmeli
lütfen eğitim ve test için kullanın. Kötüye kullandığınızda sorumluluk bana ait değildir.🙏🏻
