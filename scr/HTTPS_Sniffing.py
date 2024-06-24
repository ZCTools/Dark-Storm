from mitmproxy import http

print("Lütfen mitmdump -s 'senin_kodun.py' diye çalıştırın.")

def request(flow: http.HTTPFlow) -> None:
    # Istekleri yakala ve bilgileri göster
    print(f"Istekler(Requests): {flow.request.url}")
    print(f"Başlıklar(Headers): {flow.request.headers}")

def response(flow: http.HTTPFlow) -> None:
    # Yanıtları yakala ve bilgileri göster
    print(f"Cevap(Response): {flow.request.url}")
    print(f"Durum kodu: {flow.response.status_code}")
    print(f"Bağlantı: {flow.response.text[:200]}")  # Ilk 200 karakteri göster
