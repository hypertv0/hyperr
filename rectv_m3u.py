import requests
import json
import time
import os

# --- SMALI ANALİZİNDEN ÇIKARILAN GİZLİ BAŞLIKLAR ---
API_KEY = "AIzaSyBbhpzG8Ecohu9yArfCO5tF13BQLhjLahc" # RecTV$Companion içinde bulundu
APP_ID = "1:791583031279:android:244c3d507ab299fcabc01a"
APP_VERSION = "19.2.2"
PACKAGE_NAME = "com.rectv.shot"
SW_KEY = "4F5A9C3D9A86FA54EACEDDD635185/c3c5bd17-e37b-4b94-a944-8a3688a30452"

# Bazen domain değişebilir, Smali'deki varsayılan:
BASE_URL = "https://m.prectv60.lol"

CATEGORIES = [
    {"title": "Canlı TV", "url": "/api/channel/by/filtres/0/0/1/"},
    {"title": "Son Filmler", "url": "/api/movie/by/filtres/0/created/1/"},
    {"title": "Türkçe Dublaj", "url": "/api/movie/by/filtres/26/created/1/"},
    {"title": "Türkçe Altyazı", "url": "/api/movie/by/filtres/27/created/1/"},
    {"title": "Son Diziler", "url": "/api/serie/by/filtres/0/created/1/"},
    {"title": "Aksiyon", "url": "/api/movie/by/filtres/1/created/1/"},
    {"title": "Komedi", "url": "/api/movie/by/filtres/3/created/1/"},
    {"title": "Korku", "url": "/api/movie/by/filtres/8/created/1/"},
]

class RecTVGenerator:
    def __init__(self):
        self.session = requests.Session()
        # Smali'deki postVerify ve getRecTVDomain fonksiyonlarındaki tüm headerlar:
        self.session.headers.update({
            "User-Agent": "okhttp/4.12.0",
            "X-Android-Package": PACKAGE_NAME,
            "X-Goog-Api-Key": API_KEY,
            "appVersion": APP_VERSION,
            "appId": APP_ID,
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8"
        })
        self.token = ""

    def authenticate(self):
        print("Kimlik doğrulama başlatılıyor...")
        try:
            # 1. Adım: Nonce Al (Geçici Token)
            nonce_url = f"{BASE_URL}/api/attest/nonce"
            resp = self.session.get(nonce_url)
            
            if resp.status_code != 200:
                print(f"Nonce Hatası: {resp.status_code} - {resp.text}")
                return False
            
            data = resp.json()
            temp_token = data.get("token")
            
            if not temp_token:
                print("Token bulunamadı.")
                return False

            print("Geçici token alındı, doğrulanıyor...")

            # 2. Adım: Verify (Doğrulama)
            # Smali analizine göre burada Authorization header güncellenmeli
            verify_url = f"{BASE_URL}/api/attest/verify"
            self.session.headers.update({"Authorization": f"Bearer {temp_token}"})
            
            # Verify isteği boş bir JSON body göndermeli
            verify_resp = self.session.post(verify_url, json={})
            
            if verify_resp.status_code == 200:
                print("✅ Token başarıyla doğrulandı!")
                self.token = temp_token
                return True
            else:
                # Bazen verify başarısız olsa bile token okuma (read-only) için çalışabilir.
                print(f"⚠️ Verify uyarısı: {verify_resp.status_code}. Yine de devam ediliyor...")
                self.token = temp_token
                return True

        except Exception as e:
            print(f"Auth Exception: {e}")
            return False

    def fetch_items(self, endpoint_template):
        if not self.token:
            return []
            
        full_url = f"{BASE_URL}{endpoint_template}{SW_KEY}"
        try:
            resp = self.session.get(full_url)
            if resp.status_code == 200:
                return resp.json()
            else:
                print(f"Veri çekilemedi ({resp.status_code}): {endpoint_template}")
                return []
        except Exception as e:
            print(f"Fetch Hatası: {e}")
            return []

    def generate_m3u(self):
        # Dosyayı baştan oluşturuyoruz ki hata olsa bile boş dosya olsun (Git hatasını önlemek için)
        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")

        if not self.authenticate():
            print("Auth başarısız oldu, işlem durduruluyor.")
            return

        m3u_content = "#EXTM3U\n"
        total_count = 0

        for cat in CATEGORIES:
            print(f">> Kategori taranıyor: {cat['title']}")
            items = self.fetch_items(cat['url'])
            
            if not items:
                continue

            for item in items:
                title = item.get("title", "Bilinmeyen")
                image = item.get("image", "")
                sources = item.get("sources", [])
                
                # Canlı TV veya hazır linki olanları al
                if sources and len(sources) > 0:
                    link = sources[0].get("url")
                    
                    if link:
                        # Hatalı veya test linklerini filtrele
                        if "otolinkaff" in link: 
                            continue

                        m3u_content += f'#EXTINF:-1 group-title="{cat["title"]}" tvg-logo="{image}", {title}\n'
                        m3u_content += f'{link}\n'
                        total_count += 1

        # Dosyayı kaydet
        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write(m3u_content)
        
        print(f"İşlem tamamlandı. Toplam {total_count} içerik eklendi.")

if __name__ == "__main__":
    try:
        generator = RecTVGenerator()
        generator.generate_m3u()
    except Exception as e:
        print(f"Kritik Hata: {e}")
        # Hata olsa bile dosyanın var olduğundan emin ol
        if not os.path.exists("playlist.m3u"):
            with open("playlist.m3u", "w") as f:
                f.write("#EXTM3U\n")
