import requests
import json
import os
import random
import time

# --- SMALI KODUNDAN ÇIKARILAN SABİTLER ---
# Firebase Config (Domain bulmak için)
FB_API_KEY = "AIzaSyBbhpzG8Ecohu9yArfCO5tF13BQLhjLahc"
FB_APP_ID = "1:791583031279:android:244c3d507ab299fcabc01a"
FB_PROJECT_ID = "791583031279"
PACKAGE_NAME = "com.rectv.shot"

# API Parametreleri
SW_KEY = "4F5A9C3D9A86FA54EACEDDD635185/c3c5bd17-e37b-4b94-a944-8a3688a30452"

# Smali 'loadLinks' fonksiyonunda bulunan bypass domainleri
BYPASS_DOMAINS = [
    "https://uzaycorbasi.lol/",
    "https://nextpulse.sbs/",
    "https://uzayterligi.lol/",
    "https://firinmakinesi.lol/"
]

# Kategoriler (SAYFA parametresi 1 olarak ayarlandı)
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
        # Smali kodundaki gibi okhttp taklidi yapıyoruz
        self.session.headers.update({
            "User-Agent": "okhttp/4.12.0",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Accept": "application/json"
        })
        self.base_url = None
        self.token = None

    def get_firebase_domain(self):
        """Firebase'den güncel domaini çeker"""
        print("🌍 Güncel adres Firebase üzerinden sorgulanıyor...")
        url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{FB_PROJECT_ID}/namespaces/firebase:fetch"
        headers = {
            "X-Goog-Api-Key": FB_API_KEY,
            "X-Android-Package": PACKAGE_NAME,
            "Content-Type": "application/json"
        }
        body = {
            "appId": FB_APP_ID,
            "appInstanceId": "randomId123",
            "appVersion": "19.2.2"
        }
        
        try:
            r = requests.post(url, headers=headers, json=body, timeout=10)
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
        
        # Firebase çalışmazsa manuel fallback
        print("⚠️ Firebase başarısız, varsayılan domain kullanılıyor.")
        self.base_url = "https://m.prectv60.lol"
        return True

    def login(self):
        """Nonce ve Verify adımları"""
        if not self.base_url:
            self.get_firebase_domain()

        print("🔑 Token alınıyor...")
        nonce_url = f"{self.base_url}/api/attest/nonce"
        
        try:
            # 1. Nonce İsteği
            r = self.session.get(nonce_url, timeout=15)
            
            if r.status_code != 200:
                print(f"❌ Nonce HTTP Hatası: {r.status_code}")
                print(f"Cevap: {r.text}")
                return False

            try:
                resp_json = r.json()
            except:
                print(f"❌ JSON Parse Hatası! Gelen veri:\n{r.text}")
                return False

            token = resp_json.get("token")
            if not token:
                print(f"❌ Token bulunamadı! Gelen JSON: {resp_json}")
                return False

            # 2. Verify İsteği (Smali postVerify fonksiyonu)
            # Token'ı header'a ekle
            self.session.headers.update({"Authorization": f"Bearer {token}"})
            verify_url = f"{self.base_url}/api/attest/verify"
            
            # Verify isteği boş body ile post edilir
            self.session.post(verify_url, json={}, timeout=10)
            
            # Verify sonucu 200 olmasa bile token genellikle geçerlidir.
            print("✅ Token alındı ve yetkilendirme başlığına eklendi.")
            self.token = token
            return True

        except Exception as e:
            print(f"❌ Login Exception: {e}")
            return False

    def process_link(self, raw_link):
        """Smali loadLinks fonksiyonundaki domain değiştirme mantığı"""
        if not raw_link: return None
        
        # Otolinkaff reklam linklerini filtrele
        if "otolinkaff" in raw_link:
            return None

        # Cloudflare Workers linklerini bypass et
        if "1.cf32-2c8.workers.dev" in raw_link:
            random_domain = random.choice(BYPASS_DOMAINS)
            # .dev/'den sonrasını al
            path = raw_link.split(".dev/")[-1]
            new_link = f"{random_domain}{path}"
            return new_link
            
        return raw_link

    def get_content(self):
        if not self.login():
            return "#EXTM3U\n"

        m3u = "#EXTM3U\n"
        count = 0

        for cat in CATEGORIES:
            print(f"📂 Kategori taranıyor: {cat['title']}")
            url = f"{self.base_url}{cat['url']}{SW_KEY}"
            
            try:
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
                                    m3u += f'#EXTINF:-1 group-title="{cat["title"]}" tvg-logo="{image}",{title}\n'
                                    m3u += f"{final_url}\n"
                                    count += 1
            except Exception as e:
                print(f"⚠️ Kategori hatası ({cat['title']}): {e}")

        print(f"🎉 Toplam {count} içerik listeye eklendi.")
        return m3u

if __name__ == "__main__":
    app = RecTV()
    playlist = app.get_content()
    
    with open("playlist.m3u", "w", encoding="utf-8") as f:
        f.write(playlist)
