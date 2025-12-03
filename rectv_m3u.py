import requests
import json
import os
import random
import time

# --- AYARLAR ---
MAX_PAGES = 200  # Her kategori için taranacak sayfa sayısı (Binlerce içerik için yüksek tutuldu)
TIMEOUT = 15     # Zaman aşımı

# --- SABİTLER ---
FB_API_KEY = "AIzaSyBbhpzG8Ecohu9yArfCO5tF13BQLhjLahc"
FB_APP_ID = "1:791583031279:android:244c3d507ab299fcabc01a"
FB_PROJECT_ID = "791583031279"
PACKAGE_NAME = "com.rectv.shot"
SW_KEY = "4F5A9C3D9A86FA54EACEDDD635185/c3c5bd17-e37b-4b94-a944-8a3688a30452"

BYPASS_DOMAINS = [
    "https://uzaycorbasi.lol/",
    "https://nextpulse.sbs/",
    "https://uzayterligi.lol/",
    "https://firinmakinesi.lol/"
]

CATEGORIES = [
    {"title": "Canlı TV", "url": "/api/channel/by/filtres/0/0/{page}/", "type": "live"},
    {"title": "Son Filmler", "url": "/api/movie/by/filtres/0/created/{page}/", "type": "movie"},
    {"title": "Son Diziler", "url": "/api/serie/by/filtres/0/created/{page}/", "type": "serie"},
    {"title": "Türkçe Dublaj", "url": "/api/movie/by/filtres/26/created/{page}/", "type": "movie"},
    {"title": "Türkçe Altyazı", "url": "/api/movie/by/filtres/27/created/{page}/", "type": "movie"},
    {"title": "Aksiyon", "url": "/api/movie/by/filtres/1/created/{page}/", "type": "movie"},
    {"title": "Komedi", "url": "/api/movie/by/filtres/3/created/{page}/", "type": "movie"},
    {"title": "Korku", "url": "/api/movie/by/filtres/8/created/{page}/", "type": "movie"},
    {"title": "Bilim Kurgu", "url": "/api/movie/by/filtres/4/created/{page}/", "type": "movie"},
    {"title": "Animasyon", "url": "/api/movie/by/filtres/13/created/{page}/", "type": "movie"}
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
        self.seen_ids = set()

    def get_firebase_domain(self):
        print("🌍 Güncel adres aranıyor...")
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
        except: pass
        self.base_url = "https://m.prectv60.lol"
        print(f"⚠️ Varsayılan Domain: {self.base_url}")

    def login(self):
        if not self.base_url: self.get_firebase_domain()
        try:
            r = self.session.get(f"{self.base_url}/api/attest/nonce", timeout=TIMEOUT)
            data = r.json()
            token = data.get("token") or data.get("nonce")
            if not token: return False
            self.session.headers.update({"Authorization": f"Bearer {token}"})
            self.session.post(f"{self.base_url}/api/attest/verify", json={}, timeout=TIMEOUT)
            self.token = token
            print("✅ Token alındı.")
            return True
        except: return False

    def process_link(self, raw_link):
        if not raw_link or "otolinkaff" in raw_link: return None
        if "1.cf32-2c8.workers.dev" in raw_link:
            return f"{random.choice(BYPASS_DOMAINS)}{raw_link.split('.dev/')[-1]}"
        return raw_link

    # --- YENİ: DİZİ BÖLÜMLERİNİ ÇEKEN FONKSİYON ---
    def fetch_series_episodes(self, series_id, series_title, cat_title, series_image):
        """Dizinin sezon ve bölümlerini çeker"""
        url = f"{self.base_url}/api/season/by/serie/{series_id}/{SW_KEY}"
        m3u_entries = ""
        count = 0
        
        try:
            r = self.session.get(url, timeout=TIMEOUT)
            if r.status_code == 200:
                seasons = r.json()
                if isinstance(seasons, list):
                    for season in seasons:
                        episodes = season.get("episodes", [])
                        for ep in episodes:
                            ep_title = ep.get("title", f"Bölüm {ep.get('id')}")
                            full_title = f"{series_title} - {ep_title}"
                            sources = ep.get("sources", [])
                            
                            if sources:
                                raw_url = sources[0].get("url")
                                final_url = self.process_link(raw_url)
                                
                                if final_url:
                                    # Dizi ID + Bölüm ID kombinasyonu ile duplicate kontrolü
                                    unique_ep_id = f"S{series_id}E{ep.get('id')}"
                                    if unique_ep_id not in self.seen_ids:
                                        m3u_entries += f'#EXTINF:-1 group-title="{cat_title}" tvg-logo="{series_image}" http-referrer="https://twitter.com/",{full_title}\n'
                                        m3u_entries += f"{final_url}\n"
                                        self.seen_ids.add(unique_ep_id)
                                        count += 1
        except Exception as e:
            print(f"   ⚠️ Dizi Hatası ({series_title}): {e}")
            
        return m3u_entries, count

    def get_content(self):
        if not self.login(): return "#EXTM3U\n"

        m3u_content = "#EXTM3U\n"
        total_count = 0

        for cat in CATEGORIES:
            print(f"\n📂 Kategori: {cat['title']} ({cat['type']})")
            
            for page in range(1, MAX_PAGES + 1):
                url = f"{self.base_url}{cat['url'].format(page=page)}{SW_KEY}"
                
                try:
                    r = self.session.get(url, timeout=TIMEOUT)
                    # Eğer 200 değilse veya boş ise kategori bitmiştir
                    if r.status_code != 200: break
                    data = r.json()
                    if not data or not isinstance(data, list) or len(data) == 0:
                        print(f"   -> Sayfa {page} boş, kategori tamamlandı.")
                        break

                    page_added = 0
                    
                    for item in data:
                        item_id = item.get("id")
                        title = item.get("title", "Bilinmeyen").strip().replace(",", " ")
                        image = item.get("image", "")
                        
                        # --- TİP KONTROLÜ ---
                        # Eğer bu bir Dizi ise (Serie)
                        if cat['type'] == "serie" or item.get("type") == "serie":
                            # Diziyi duplicate kontrolüne sokma, bölümleri kontrol ediyoruz
                            entries, s_count = self.fetch_series_episodes(item_id, title, cat['title'], image)
                            m3u_content += entries
                            page_added += s_count
                            total_count += s_count
                            
                        # Eğer Film veya Canlı TV ise
                        else:
                            if item_id in self.seen_ids: continue
                            self.seen_ids.add(item_id)
                            
                            sources = item.get("sources", [])
                            if sources:
                                raw_url = sources[0].get("url")
                                final_url = self.process_link(raw_url)
                                if final_url:
                                    m3u_content += f'#EXTINF:-1 group-title="{cat["title"]}" tvg-logo="{image}" http-referrer="https://twitter.com/",{title}\n'
                                    m3u_content += f"{final_url}\n"
                                    page_added += 1
                                    total_count += 1
                    
                    print(f"   -> Sayfa {page}: {page_added} içerik tarandı.")
                    
                    # ÖNEMLİ DÜZELTME:
                    # page_added == 0 olsa bile BREAK YAPMIYORUZ.
                    # Çünkü belki bu sayfadaki tüm filmler "Son Filmler"den dolayı zaten eklenmiştir
                    # ama bir sonraki sayfada yeni filmler olabilir.
                    
                except Exception as e:
                    print(f"   -> Sayfa Hatası: {e}")
                    break

        print(f"\n🎉 TOPLAM {total_count} İÇERİK.")
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
