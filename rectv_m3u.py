import requests
import json
import os
import random
import time

# --- AYARLAR ---
MAX_PAGES = 50  # Her kategori için maksimum kaç sayfa taranacak? (Sınırı artırabilirsin)
TIMEOUT = 10    # İstek zaman aşımı (saniye)

# --- SABİTLER ---
FB_API_KEY = "AIzaSyBbhpzG8Ecohu9yArfCO5tF13BQLhjLahc"
FB_APP_ID = "1:791583031279:android:244c3d507ab299fcabc01a"
FB_PROJECT_ID = "791583031279"
PACKAGE_NAME = "com.rectv.shot"
SW_KEY = "4F5A9C3D9A86FA54EACEDDD635185/c3c5bd17-e37b-4b94-a944-8a3688a30452"

# Worker Bypass Domainleri
BYPASS_DOMAINS = [
    "https://uzaycorbasi.lol/",
    "https://nextpulse.sbs/",
    "https://uzayterligi.lol/",
    "https://firinmakinesi.lol/"
]

# URL yapılarında {page} yer tutucusu kullanıyoruz
CATEGORIES = [
    {"title": "Canlı TV", "url": "/api/channel/by/filtres/0/0/{page}/"},
    {"title": "Son Filmler", "url": "/api/movie/by/filtres/0/created/{page}/"},
    {"title": "Türkçe Dublaj", "url": "/api/movie/by/filtres/26/created/{page}/"},
    {"title": "Türkçe Altyazı", "url": "/api/movie/by/filtres/27/created/{page}/"},
    {"title": "Son Diziler", "url": "/api/serie/by/filtres/0/created/{page}/"},
    {"title": "Aksiyon", "url": "/api/movie/by/filtres/1/created/{page}/"},
    {"title": "Komedi", "url": "/api/movie/by/filtres/3/created/{page}/"},
    {"title": "Korku", "url": "/api/movie/by/filtres/8/created/{page}/"},
    {"title": "Aile", "url": "/api/movie/by/filtres/14/created/{page}/"},
    {"title": "Bilim Kurgu", "url": "/api/movie/by/filtres/4/created/{page}/"}
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
        self.seen_ids = set() # Aynı içerikleri tekrar eklememek için

    def get_firebase_domain(self):
        print("🌍 Güncel adres aranıyor...")
        # Firebase başarısız olursa diye manuel liste
        manual_fallbacks = [
            "https://m.prectv60.lol",
            "https://m.prectv61.lol",
            "http://m.rectv.xyz"
        ]
        
        # Önce Firebase
        try:
            url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{FB_PROJECT_ID}/namespaces/firebase:fetch"
            body = {"appId": FB_APP_ID, "appInstanceId": "valid_id", "appVersion": "19.2.2"}
            r = requests.post(url, json=body, timeout=5)
            if r.status_code == 200:
                api_url = r.json().get("entries", {}).get("api_url")
                if api_url:
                    self.base_url = api_url.replace("/api/", "").rstrip("/")
                    print(f"✅ Firebase Domain: {self.base_url}")
                    return
        except:
            pass

        # Firebase olmazsa manuel dene
        print("⚠️ Firebase yanıt vermedi, manuel domainler deneniyor...")
        for domain in manual_fallbacks:
            try:
                r = self.session.get(f"{domain}/api/attest/nonce", timeout=3)
                if r.status_code == 200:
                    self.base_url = domain
                    print(f"✅ Çalışan Domain: {domain}")
                    return
            except:
                continue
        
        # Hiçbiri çalışmazsa varsayılan
        self.base_url = "https://m.prectv60.lol"

    def login(self):
        if not self.base_url: self.get_firebase_domain()
        
        try:
            r = self.session.get(f"{self.base_url}/api/attest/nonce", timeout=TIMEOUT)
            data = r.json()
            # Token veya Nonce hangisi varsa al
            token = data.get("token") or data.get("nonce")
            
            if not token:
                print("❌ Token alınamadı.")
                return False

            self.session.headers.update({"Authorization": f"Bearer {token}"})
            # Verify formalite, 400 dönse de devam ediyoruz
            self.session.post(f"{self.base_url}/api/attest/verify", json={}, timeout=TIMEOUT)
            self.token = token
            print("✅ Token alındı.")
            return True
        except Exception as e:
            print(f"❌ Login Hatası: {e}")
            return False

    def process_link(self, raw_link):
        if not raw_link or "otolinkaff" in raw_link: return None
        if "1.cf32-2c8.workers.dev" in raw_link:
            return f"{random.choice(BYPASS_DOMAINS)}{raw_link.split('.dev/')[-1]}"
        return raw_link

    def get_content(self):
        if not self.login(): return "#EXTM3U\n"

        m3u_content = "#EXTM3U\n"
        total_count = 0

        for cat in CATEGORIES:
            print(f"\n📂 Kategori Başlıyor: {cat['title']}")
            
            for page in range(1, MAX_PAGES + 1):
                # {page} kısmını gerçek sayfa numarasıyla değiştir
                url = f"{self.base_url}{cat['url'].format(page=page)}{SW_KEY}"
                
                try:
                    # Sunucuyu yormamak için minik bekleme
                    time.sleep(0.2)
                    
                    r = self.session.get(url, timeout=TIMEOUT)
                    if r.status_code != 200:
                        print(f"   -> Sayfa {page} bitti veya hata (Kod: {r.status_code})")
                        break
                    
                    data = r.json()
                    if not data or not isinstance(data, list) or len(data) == 0:
                        print(f"   -> Sayfa {page} boş, kategori tamamlandı.")
                        break

                    page_added = 0
                    for item in data:
                        # ID kontrolü (Sonsuz döngü veya tekrarı önlemek için)
                        item_id = item.get("id")
                        if item_id in self.seen_ids:
                            continue
                        
                        self.seen_ids.add(item_id)
                        
                        title = item.get("title", "Bilinmeyen").strip().replace(",", " ")
                        image = item.get("image", "")
                        sources = item.get("sources", [])
                        
                        if sources:
                            raw_url = sources[0].get("url")
                            final_url = self.process_link(raw_url)
                            
                            if final_url:
                                m3u_content += f'#EXTINF:-1 group-title="{cat["title"]}" tvg-logo="{image}" http-referrer="https://twitter.com/",{title}\n'
                                m3u_content += f"{final_url}\n"
                                page_added += 1
                                total_count += 1
                    
                    print(f"   -> Sayfa {page}: {page_added} içerik eklendi.")
                    
                    # Eğer bu sayfada hiç yeni içerik yoksa diğer sayfalara bakmaya gerek yok
                    if page_added == 0:
                        break

                except Exception as e:
                    print(f"   -> Sayfa Hatası: {e}")
                    break

        print(f"\n🎉 TOPLAM {total_count} İÇERİK M3U DOSYASINA YAZILDI.")
        return m3u_content

if __name__ == "__main__":
    try:
        app = RecTV()
        playlist = app.get_content()
        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write(playlist)
    except Exception as e:
        print(f"Kritik Hata: {e}")
        if not os.path.exists("playlist.m3u"):
            with open("playlist.m3u", "w") as f:
                f.write("#EXTM3U\n")
