import requests
import json
import time
import os
import random

# --- SABİTLER ---
# Firebase Config Bilgileri (Smali'den alındı)
FB_API_KEY = "AIzaSyBbhpzG8Ecohu9yArfCO5tF13BQLhjLahc"
FB_APP_ID = "1:791583031279:android:244c3d507ab299fcabc01a"
FB_PROJECT_ID = "791583031279"
PACKAGE_NAME = "com.rectv.shot"
SW_KEY = "4F5A9C3D9A86FA54EACEDDD635185/c3c5bd17-e37b-4b94-a944-8a3688a30452"

# Eğer Firebase çalışmazsa denenecek yedek adresler
FALLBACK_DOMAINS = [
    "https://m.prectv60.lol",
    "https://m.prectv61.lol",
    "https://m.prectv62.lol",
    "http://m.rectv.xyz"
]

CATEGORIES = [
    {"title": "Canlı TV", "url": "/api/channel/by/filtres/0/0/1/"},
    {"title": "Son Filmler", "url": "/api/movie/by/filtres/0/created/1/"},
    {"title": "Türkçe Dublaj", "url": "/api/movie/by/filtres/26/created/1/"},
    {"title": "Türkçe Altyazı", "url": "/api/movie/by/filtres/27/created/1/"},
    {"title": "Son Diziler", "url": "/api/serie/by/filtres/0/created/1/"},
    {"title": "Aile", "url": "/api/movie/by/filtres/14/created/1/"},
    {"title": "Aksiyon", "url": "/api/movie/by/filtres/1/created/1/"},
    {"title": "Animasyon", "url": "/api/movie/by/filtres/13/created/1/"},
    {"title": "Komedi", "url": "/api/movie/by/filtres/3/created/1/"},
    {"title": "Korku", "url": "/api/movie/by/filtres/8/created/1/"},
]

class RecTVGenerator:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "okhttp/4.12.0",
            "Accept": "application/json"
        })
        self.base_url = None
        self.token = ""

    def get_dynamic_domain(self):
        """Firebase Remote Config'den güncel API adresini çeker"""
        print("Güncel domain aranıyor (Firebase)...")
        url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{FB_PROJECT_ID}/namespaces/firebase:fetch"
        
        headers = {
            "X-Goog-Api-Key": FB_API_KEY,
            "X-Android-Package": PACKAGE_NAME,
            "Content-Type": "application/json"
        }
        
        body = {
            "appId": FB_APP_ID,
            "appInstanceId": "ck4YSh5sTEac3JSbEWyURI", # Rastgele bir ID
            "appVersion": "19.2.2"
        }

        try:
            resp = requests.post(url, headers=headers, json=body, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                # JSON yapısı içinden api_url'yi bulmaya çalışıyoruz
                # Genellikle entries -> api_url şeklinde döner
                entries = data.get("entries", {})
                api_url = entries.get("api_url")
                
                if api_url:
                    # Gelen url bazen "/api/" ile biter, temizleyelim
                    clean_url = api_url.replace("/api/", "").rstrip("/")
                    print(f"✅ Güncel Domain Bulundu: {clean_url}")
                    return clean_url
        except Exception as e:
            print(f"Firebase hatası: {e}")
        
        print("Firebase başarısız, yedek domainler deneniyor...")
        return None

    def find_working_domain(self):
        # 1. Önce Firebase'i dene
        domain = self.get_dynamic_domain()
        if domain:
            self.base_url = domain
            return True

        # 2. Olmazsa manuel listeyi dene
        for domain in FALLBACK_DOMAINS:
            try:
                print(f"Deneniyor: {domain}")
                resp = self.session.get(f"{domain}/api/attest/nonce", timeout=5)
                if resp.status_code == 200:
                    print(f"✅ Çalışan Domain Bulundu: {domain}")
                    self.base_url = domain
                    return True
            except:
                pass
        
        return False

    def authenticate(self):
        if not self.find_working_domain():
            print("❌ Hiçbir domain çalışmıyor!")
            return False

        print(f"Kimlik doğrulama başlatılıyor: {self.base_url}")
        try:
            # 1. Nonce Al
            nonce_url = f"{self.base_url}/api/attest/nonce"
            resp = self.session.get(nonce_url, timeout=10)
            
            if resp.status_code != 200:
                print(f"Nonce Hatası: {resp.status_code} | {resp.text}")
                return False
            
            try:
                data = resp.json()
                temp_token = data.get("token")
            except:
                print("Nonce yanıtı JSON değil!")
                return False
            
            if not temp_token:
                print("Token JSON içinde bulunamadı.")
                return False

            # 2. Verify
            verify_url = f"{self.base_url}/api/attest/verify"
            self.session.headers.update({"Authorization": f"Bearer {temp_token}"})
            
            # Verify bazen 400 verse de token geçerli olabiliyor, yine de deniyoruz.
            verify_resp = self.session.post(verify_url, json={}, timeout=10)
            
            # Token'ı her türlü kaydediyoruz
            self.token = temp_token
            return True

        except Exception as e:
            print(f"Auth Exception: {e}")
            return False

    def fetch_items(self, endpoint_template):
        if not self.base_url or not self.token:
            return []
            
        full_url = f"{self.base_url}{endpoint_template}{SW_KEY}"
        try:
            # Token header'da zaten var
            resp = self.session.get(full_url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            return []
        except:
            return []

    def generate_m3u(self):
        # Dosyayı sıfırla
        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")

        if not self.authenticate():
            print("Auth başarısız, işlem sonlandırıldı.")
            return

        m3u_content = "#EXTM3U\n"
        total_count = 0

        for cat in CATEGORIES:
            print(f">> Taranıyor: {cat['title']}")
            items = self.fetch_items(cat['url'])
            
            if not items:
                continue

            for item in items:
                title = item.get("title", "Bilinmeyen").replace(",", " ") # Virgülleri temizle
                image = item.get("image", "")
                sources = item.get("sources", [])
                
                if sources and len(sources) > 0:
                    link = sources[0].get("url")
                    
                    if link and "otolinkaff" not in link:
                        m3u_content += f'#EXTINF:-1 group-title="{cat["title"]}" tvg-logo="{image}", {title}\n'
                        m3u_content += f'{link}\n'
                        total_count += 1

        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write(m3u_content)
        
        print(f"✅ Tamamlandı. Toplam {total_count} içerik.")

if __name__ == "__main__":
    try:
        gen = RecTVGenerator()
        gen.generate_m3u()
    except Exception as e:
        print(f"Genel Hata: {e}")
        # Hata durumunda dosya boş kalmasın diye kontrol
        if not os.path.exists("playlist.m3u"):
             with open("playlist.m3u", "w") as f:
                f.write("#EXTM3U\n")
