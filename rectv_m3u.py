import requests
import json
import os
import random
import time

# --- SMALI ANALİZİ SABİTLERİ ---
FB_API_KEY = "AIzaSyBbhpzG8Ecohu9yArfCO5tF13BQLhjLahc"
FB_APP_ID = "1:791583031279:android:244c3d507ab299fcabc01a"
FB_PROJECT_ID = "791583031279"
PACKAGE_NAME = "com.rectv.shot"
SW_KEY = "4F5A9C3D9A86FA54EACEDDD635185/c3c5bd17-e37b-4b94-a944-8a3688a30452"

# Worker Bypass Domainleri (Smali loadLinks fonksiyonundan)
BYPASS_DOMAINS = [
    "https://uzaycorbasi.lol/",
    "https://nextpulse.sbs/",
    "https://uzayterligi.lol/",
    "https://firinmakinesi.lol/"
]

CATEGORIES = [
    {"title": "Canlı TV", "url": "/api/channel/by/filtres/0/0/1/"},
    {"title": "Son Filmler", "url": "/api/movie/by/filtres/0/created/1/"},
    {"title": "Türkçe Dublaj", "url": "/api/movie/by/filtres/26/created/1/"},
    {"title": "Türkçe Altyazı", "url": "/api/movie/by/filtres/27/created/1/"},
    {"title": "Son Diziler", "url": "/api/serie/by/filtres/0/created/1/"},
    {"title": "Aksiyon", "url": "/api/movie/by/filtres/1/created/1/"},
    {"title": "Komedi", "url": "/api/movie/by/filtres/3/created/1/"},
    {"title": "Korku", "url": "/api/movie/by/filtres/8/created/1/"}
]

class RecTV:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "okhttp/4.12.0",
            "Accept": "application/json",
            "Connection": "Keep-Alive",
            "X-Android-Package": PACKAGE_NAME,
            "X-Goog-Api-Key": FB_API_KEY
        })
        self.base_url = None
        self.token = None

    def get_firebase_domain(self):
        print("🌍 Güncel adres Firebase üzerinden sorgulanıyor...")
        url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{FB_PROJECT_ID}/namespaces/firebase:fetch"
        
        body = {
            "appId": FB_APP_ID,
            "appInstanceId": "randomId123",
            "appVersion": "19.2.2"
        }
        
        try:
            r = requests.post(url, json=body, timeout=10)
            if r.status_code == 200:
                data = r.json()
                api_url = data.get("entries", {}).get("api_url")
                if api_url:
                    clean_url = api_url.replace("/api/", "").rstrip("/")
                    print(f"✅ Domain Bulundu: {clean_url}")
                    self.base_url = clean_url
                    return True
        except Exception as e:
            print(f"⚠️ Firebase Hatası: {e}")
        
        print("⚠️ Firebase başarısız, varsayılan domain kullanılıyor.")
        self.base_url = "https://m.prectv60.lol"
        return True

    def login(self):
        if not self.base_url:
            self.get_firebase_domain()

        print("🔑 Token alınıyor...")
        nonce_url = f"{self.base_url}/api/attest/nonce"
        
        try:
            # 1. Nonce İsteği
            r = self.session.get(nonce_url, timeout=15)
            
            if r.status_code != 200:
                print(f"❌ Nonce HTTP Hatası: {r.status_code}")
                return False

            try:
                resp_json = r.json()
            except:
                print(f"❌ JSON Parse Hatası: {r.text}")
                return False

            # DÜZELTME BURADA: Hem 'token' hem 'nonce' anahtarlarını kontrol ediyoruz.
            token = resp_json.get("token") or resp_json.get("nonce")
            
            if not token:
                print(f"❌ Token/Nonce bulunamadı! Gelen JSON: {resp_json}")
                return False

            # 2. Verify İsteği
            verify_url = f"{self.base_url}/api/attest/verify"
            
            # Token'ı header'a ekle (Bearer Token olarak)
            self.session.headers.update({"Authorization": f"Bearer {token}"})
            
            # Verify isteği (Boş body ile)
            v = self.session.post(verify_url, json={}, timeout=10)
            
            # Verify sonucu 200 dönmese bile token genellikle okuma işlemleri için geçerlidir.
            if v.status_code == 200:
                print("✅ Token başarıyla doğrulandı.")
            else:
                print(f"⚠️ Token doğrulama uyarısı ({v.status_code}), ama devam ediliyor.")

            self.token = token
            return True

        except Exception as e:
            print(f"❌ Login Exception: {e}")
            return False

    def process_link(self, raw_link):
        if not raw_link: return None
        
        if "otolinkaff" in raw_link: return None

        # Worker Bypass (Smali loadLinks fonksiyonu)
        if "1.cf32-2c8.workers.dev" in raw_link:
            random_domain = random.choice(BYPASS_DOMAINS)
            path = raw_link.split(".dev/")[-1]
            return f"{random_domain}{path}"
            
        return raw_link

    def get_content(self):
        # Dosyayı baştan oluştur
        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")

        if not self.login():
            return

        m3u_content = "#EXTM3U\n"
        count = 0

        for cat in CATEGORIES:
            print(f"📂 Taranıyor: {cat['title']}")
            url = f"{self.base_url}{cat['url']}{SW_KEY}"
            
            try:
                # Token zaten session header'ında var
                r = self.session.get(url, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    if isinstance(data, list):
                        for item in data:
                            title = item.get("title", "Bilinmeyen").strip().replace(",", " ")
                            image = item.get("image", "")
                            sources = item.get("sources", [])
                            
                            if sources:
                                raw_url = sources[0].get("url")
                                final_url = self.process_link(raw_url)
                                
                                if final_url:
                                    # Smali loadLinks referer header taklidi
                                    m3u_content += f'#EXTINF:-1 group-title="{cat["title"]}" tvg-logo="{image}" http-referrer="https://twitter.com/",{title}\n'
                                    m3u_content += f"{final_url}\n"
                                    count += 1
            except Exception as e:
                print(f"⚠️ Hata ({cat['title']}): {e}")

        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write(m3u_content)
        
        print(f"🎉 İşlem Bitti. Toplam {count} içerik eklendi.")

if __name__ == "__main__":
    try:
        app = RecTV()
        app.get_content()
    except Exception as e:
        print(f"Kritik Hata: {e}")
        if not os.path.exists("playlist.m3u"):
            with open("playlist.m3u", "w") as f:
                f.write("#EXTM3U\n")
