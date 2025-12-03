import requests
import json
import time
import os

# Smali kodundan alınan sabitler
SW_KEY = "4F5A9C3D9A86FA54EACEDDD635185/c3c5bd17-e37b-4b94-a944-8a3688a30452"
BASE_URL_FALLBACK = "https://m.prectv60.lol"
USER_AGENT = "okhttp/4.12.0"

# Kategoriler (Smali kodundaki 'getMainPage' fonksiyonundan)
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
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-Android-Package": "com.rectv.shot",
            "Accept": "application/json"
        })
        self.base_url = BASE_URL_FALLBACK
        self.token = ""

    def authenticate(self):
        """Token alma işlemi (getRecToken ve postVerify mantığı)"""
        try:
            # 1. Nonce al
            nonce_url = f"{self.base_url}/api/attest/nonce"
            resp = self.session.get(nonce_url)
            if resp.status_code != 200:
                print("Nonce alınamadı.")
                return False
            
            # JSON parse et (Smali'deki AuthResponse)
            data = resp.json()
            temp_token = data.get("token")
            
            # 2. Verify et
            verify_url = f"{self.base_url}/api/attest/verify"
            # Header'a geçici token'ı ekle
            self.session.headers.update({"Authorization": f"Bearer {temp_token}"})
            
            verify_resp = self.session.post(verify_url, json={})
            if verify_resp.status_code == 200:
                print("Token başarıyla doğrulandı!")
                self.token = temp_token
                return True
            else:
                print(f"Verify hatası: {verify_resp.text}")
                return False
        except Exception as e:
            print(f"Auth Hatası: {e}")
            return False

    def fetch_items(self, endpoint_template):
        """Belirtilen kategorideki içerikleri çeker"""
        # URL'deki 'SAYFA' kısmını '1' yaptık, SW_KEY ekliyoruz
        full_url = f"{self.base_url}{endpoint_template}{SW_KEY}"
        
        try:
            resp = self.session.get(full_url)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            print(f"Veri çekme hatası ({endpoint_template}): {e}")
            return []

    def get_stream_link(self, item_id, item_type):
        """
        DİKKAT: VOD (Film/Dizi) için tek tek link çekmek işlemi çok uzatır
        ve GitHub Actions süresini aşabilir. Bu örnekte sadece 'source' listesinde
        hazır link varsa alacağız. Detaylı 'load' işlemi Live TV için genelde gerekmez.
        """
        # Canlı TV ise genellikle listede kaynak gelir.
        # Film/Dizi ise detay isteği (load) gerekir.
        pass 

    def generate_m3u(self):
        if not self.authenticate():
            return

        m3u_content = "#EXTM3U\n"

        for cat in CATEGORIES:
            print(f"Kategori işleniyor: {cat['title']}")
            items = self.fetch_items(cat['url'])
            
            if not items:
                continue

            for item in items:
                # Smali'deki RecItem modeline göre mapliyoruz
                title = item.get("title", "Bilinmeyen Başlık")
                image = item.get("image", "")
                sources = item.get("sources", [])
                
                # Sadece oynatılabilir kaynağı olanları ekle
                if sources and len(sources) > 0:
                    link = sources[0].get("url")
                    
                    # Link korumalı veya şifreli olabilir, doğrudan ekliyoruz.
                    # CS3 kodunda bazı domain değiştirmeler vardı, basit tutuyoruz.
                    if link:
                        m3u_content += f'#EXTINF:-1 group-title="{cat["title"]}" tvg-logo="{image}", {title}\n'
                        m3u_content += f'{link}\n'

        with open("playlist.m3u", "w", encoding="utf-8") as f:
            f.write(m3u_content)
        print("M3U dosyası oluşturuldu: playlist.m3u")

if __name__ == "__main__":
    generator = RecTVGenerator()
    generator.generate_m3u()
