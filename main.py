from curl_cffi import requests
import json
import re
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import sys
import time

# --- AYARLAR ---
# Smali kodundaki "passphrase" (DiziPalOrijinalKt.decrypt içinde kullanılır)
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 10

# Kategori Listesi
CATEGORIES = [
    {"id": "0", "name": "Yeni Eklenen Bölümler"},
    {"id": "1", "name": "Exxen"},
    {"id": "6", "name": "Disney+"},
    {"id": "10", "name": "Netflix"},
    {"id": "53", "name": "Amazon"},
    {"id": "54", "name": "Apple+"},
    {"id": "66", "name": "BluTV"}, # ID değişebilir, genelde popülerleri aldım
    {"id": "181", "name": "TOD"},
    {"id": "242", "name": "Tabii"}
]

class CryptoUtils:
    """
    Smali: DiziPalOrijinalKt.smali -> decrypt fonksiyonu.
    PBKDF2 ile anahtar türetip AES-CBC ile çözer.
    """
    def decrypt(self, salt_hex, iv_hex, ciphertext_b64):
        try:
            salt = bytes.fromhex(salt_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # Android uygulamasında: SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
            # Key uzunluğu: 32 bytes (256 bit), Iteration: 1000 (Java default for specialized specs usually)
            key = PBKDF2(PASSPHRASE, salt, dkLen=32, count=1000, hmac_hash_module=SHA512)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode('utf-8')
        except Exception:
            return None

class DiziScraper:
    def __init__(self):
        # curl_cffi kullanarak gerçek bir Chrome tarayıcısını taklit ediyoruz
        # Bu, Cloudflare'in "Checking your browser" ekranını aşar.
        self.session = requests.Session(impersonate="chrome120")
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        })
        self.crypto = CryptoUtils()
        self.domain = self.find_domain()
        self.cKey = None
        self.cValue = None

    def find_domain(self):
        """Github'dan güncel domaini çeker."""
        print("[-] Domain listesi kontrol ediliyor...")
        try:
            # Burası requests ile yapılabilir çünkü github CF korumalı değil
            r = requests.get(DOMAIN_LIST_URL, timeout=10)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        dom = part.split(':', 1)[1].strip()
                        print(f"[OK] Domain Bulundu: {dom}")
                        return dom.rstrip('/')
        except:
            pass
        print(f"[!] Domain bulunamadı, varsayılan: {DEFAULT_DOMAIN}")
        return DEFAULT_DOMAIN

    def init_tokens(self):
        """Ana sayfaya girip cKey ve cValue değerlerini (CSRF Token) çeker."""
        print(f"[-] Siteye giriş yapılıyor: {self.domain}")
        try:
            r = self.session.get(self.domain, timeout=20)
            
            # Cloudflare kontrolü
            if "Just a moment" in r.text:
                print("[FATAL] Cloudflare aşılamadı! (curl_cffi impersonate ayarını kontrol et)")
                return False

            # Regex ile tokenları bul
            ckey = re.search(r'name="cKey" value="([^"]+)"', r.text)
            cvalue = re.search(r'name="cValue" value="([^"]+)"', r.text)

            if ckey and cvalue:
                self.cKey = ckey.group(1)
                self.cValue = cvalue.group(1)
                print("[OK] Tokenlar alındı.")
                return True
            else:
                print("[FATAL] Tokenlar (cKey/cValue) sayfada bulunamadı.")
                # Bazen site yapısı değişmiş olabilir, HTML'i debug etmek gerekebilir
                # print(r.text[:500]) 
                return False
        except Exception as e:
            print(f"[FATAL] Bağlantı hatası: {e}")
            return False

    def get_category_content(self, cat_id):
        """API'ye POST isteği atarak kategori içeriğini çeker."""
        if not self.cKey: return []
        
        url = f"{self.domain}/bg/getserielistbychannel"
        
        # Smali kodundaki form data yapısı
        data = {
            "cKey": self.cKey,
            "cValue": self.cValue,
            "curPage": "1",
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        
        # Headers (Ajax isteği olduğu belirtilmeli)
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{self.domain}/",
            "Origin": self.domain
        }

        try:
            r = self.session.post(url, data=data, headers=headers, timeout=20)
            if r.status_code == 200:
                try:
                    js = r.json()
                    html = js.get('data', {}).get('html', '')
                    
                    # Basit Regex ile HTML içinden linkleri ve isimleri al
                    # Örnek HTML: <a href="https://..." class="..."> ... <div class="...">Dizi Adı</div>
                    items = []
                    # Bu regex HTML yapısına göre hassastır, genel bir yakalama yapalım
                    matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html, re.DOTALL)
                    
                    for link, title in matches:
                        full_link = link if link.startswith("http") else f"{self.domain}{link}"
                        items.append({"title": title.strip(), "url": full_link})
                    
                    return items
                except:
                    print(f"[!] JSON parse hatası ({cat_id})")
        except Exception as e:
            print(f"[!] Kategori çekme hatası: {e}")
        return []

    def get_video_source(self, url):
        """Dizi/Film sayfasındaki şifreli veriyi çözer ve linki bulur."""
        try:
            r = self.session.get(url, timeout=15)
            
            # Smali: data-rm-k özniteliğini arar
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            
            if match:
                json_str = match.group(1)
                # HTML entity'leri temizle (&quot; -> ")
                json_str = json_str.replace('&quot;', '"')
                
                data = json.loads(json_str)
                salt = data.get('salt')
                iv = data.get('iv')
                ciphertext = data.get('ciphertext')

                if salt and iv and ciphertext:
                    decrypted = self.crypto.decrypt(salt, iv, ciphertext)
                    if decrypted:
                        # Decrypted veri genellikle bir iframe HTML'idir
                        # <iframe src="https://..." ...>
                        iframe_match = re.search(r'src="([^"]+)"', decrypted)
                        if iframe_match:
                            return self.resolve_iframe(iframe_match.group(1))
        except:
            pass
        return None

    def resolve_iframe(self, iframe_url):
        """Iframe linkine gidip gerçek m3u8/mp4'ü bulur."""
        try:
            if not iframe_url.startswith("http"):
                iframe_url = f"{self.domain}{iframe_url}"
            
            # Iframe'e git (Referer önemli)
            r = self.session.get(iframe_url, headers={"Referer": self.domain}, timeout=15)
            
            # 1. Yöntem: file: "..."
            match = re.search(r'file:\s*["\']([^"\']+)["\']', r.text)
            if match: return match.group(1)
            
            # 2. Yöntem: source: "..."
            match = re.search(r'source:\s*["\']([^"\']+)["\']', r.text)
            if match: return match.group(1)

        except:
            pass
        return None

def worker(scraper, item, category):
    """Thread worker fonksiyonu"""
    link = scraper.get_video_source(item['url'])
    if link and link.startswith("http"):
        # M3U Formatı
        return (
            f'#EXTINF:-1 group-title="{category}",{item["title"]}\n'
            f'#EXTVLCOPT:http-user-agent=Mozilla/5.0\n'
            f'#EXTVLCOPT:http-referrer={scraper.domain}/\n'
            f'{link}\n'
        )
    return None

def main():
    print("--- DiziPal Sync Başlatıldı ---")
    scraper = DiziScraper()
    
    if not scraper.init_session():
        sys.exit(1)

    playlist_data = []
    
    # ThreadPool ile hızlı tarama
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        
        for cat in CATEGORIES:
            print(f"[-] Kategori taranıyor: {cat['name']}")
            items = scraper.get_category_content(cat['id'])
            print(f"    {len(items)} içerik bulundu.")
            
            for item in items:
                futures.append(executor.submit(worker, scraper, item, cat['name']))
        
        print(f"[-] Linkler çözülüyor ({len(futures)} adet)...")
        
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                playlist_data.append(res)
            completed += 1
            if completed % 10 == 0:
                print(f"    İlerleme: {completed}/{len(futures)}")

    # Kaydet
    if playlist_data:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist_data:
                f.write(entry)
        print(f"[BAŞARILI] {len(playlist_data)} içerik kaydedildi.")
    else:
        print("[UYARI] Hiçbir link çözülemedi.")

if __name__ == "__main__":
    main()
