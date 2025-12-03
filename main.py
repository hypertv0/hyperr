from DrissionPage import ChromiumPage, ChromiumOptions
from curl_cffi import requests as crequests
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
import random

# --- AYARLAR ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com" # Yedek
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 20 # Hız için yüksek thread sayısı

# Eklentideki kategori ID'leri
CATEGORIES = [
    {"id": "0", "name": "Yeni Eklenenler"},
    {"id": "1", "name": "Exxen"},
    {"id": "6", "name": "Disney+"},
    {"id": "10", "name": "Netflix"},
    {"id": "53", "name": "Amazon"},
    {"id": "54", "name": "Apple+"},
    {"id": "66", "name": "BluTV"},
    {"id": "181", "name": "TOD"},
    {"id": "242", "name": "Tabii"}
]

class CryptoUtils:
    """AES Şifre Çözücü (Smali kodunun Python karşılığı)"""
    def decrypt(self, salt_hex, iv_hex, ciphertext_b64):
        try:
            salt = bytes.fromhex(salt_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = base64.b64decode(ciphertext_b64)
            # Java'daki PBKDF2WithHmacSHA512 algoritması
            key = PBKDF2(PASSPHRASE, salt, dkLen=32, count=1000, hmac_hash_module=SHA512)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode('utf-8')
        except:
            return None

class AuthManager:
    """Cloudflare'i geçip cKey/cValue/Cookie çalan sınıf"""
    def __init__(self):
        self.domain = self.find_domain()
        self.cookies = None
        self.ua = None
        self.cKey = None
        self.cValue = None

    def find_domain(self):
        print("[-] Domain aranıyor...")
        try:
            # Requests kütüphanesi ile Github'dan domaini al
            import requests
            r = requests.get(DOMAIN_LIST_URL, timeout=5)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        d = part.split(':', 1)[1].strip().rstrip('/')
                        print(f"[OK] Domain: {d}")
                        return d
        except: pass
        return DEFAULT_DOMAIN

    def get_auth_data(self):
        print("[-] Tarayıcı (DrissionPage) başlatılıyor...")
        
        # Linux sunucu için ayarlar
        co = ChromiumOptions()
        co.set_argument('--no-sandbox')
        co.set_argument('--disable-gpu')
        # Linux'ta olduğumuz için mecburen headless, ama DrissionPage bunu gizler
        co.set_argument('--headless=new') 
        # Eklentinin User-Agent'ını taklit et
        co.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0")
        
        page = ChromiumPage(co)
        
        try:
            print(f"[-] {self.domain} adresine gidiliyor...")
            page.get(self.domain)
            
            # Cloudflare Turnstile kontrolü (Otomatik geçer)
            if page.ele('@id=challenge-stage', timeout=2):
                 print("[-] Cloudflare Challenge algılandı, bekleniyor...")
            
            # Sayfanın yüklenmesini ve cKey inputunun gelmesini bekle (Max 40sn)
            # Eklenti: input name="cKey"
            ele = page.wait.ele('css:input[name="cKey"]', timeout=40)
            
            if ele:
                print("[OK] Site açıldı! Veriler çalınıyor...")
                self.cKey = page.ele('css:input[name="cKey"]').attr('value')
                self.cValue = page.ele('css:input[name="cValue"]').attr('value')
                self.ua = page.user_agent
                
                # Cookie'leri al
                cookies_list = page.cookies.as_dict()
                # Requests formatına çevir string olarak
                self.cookies = cookies_list
                
                print(f"[OK] Kimlik doğrulama başarılı. Token: {self.cKey[:5]}...")
                return True
            else:
                print("[FATAL] Site açıldı ama tokenlar bulunamadı.")
                print(f"Title: {page.title}")
                return False
                
        except Exception as e:
            print(f"[FATAL] Tarayıcı hatası: {e}")
            return False
        finally:
            page.quit()

class FastCrawler:
    """Çalınan verilerle API'ye saldıran sınıf"""
    def __init__(self, auth_data):
        self.domain = auth_data.domain
        self.cKey = auth_data.cKey
        self.cValue = auth_data.cValue
        self.crypto = CryptoUtils()
        
        # curl_cffi session (TLS parmak izi taklidi yapar)
        self.session = crequests.Session(impersonate="chrome110")
        self.session.cookies.update(auth_data.cookies)
        self.session.headers.update({
            "User-Agent": auth_data.ua,
            "Referer": f"{self.domain}/",
            "Origin": self.domain,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "*/*"
        })

    def get_category_items(self, cat_id):
        """API'den kategori içeriğini çeker (HIZLI)"""
        url = f"{self.domain}/bg/getserielistbychannel"
        data = {
            "cKey": self.cKey,
            "cValue": self.cValue,
            "curPage": "1",
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        
        try:
            # Cloudflare bypasslı request
            r = self.session.post(url, data=data, timeout=15)
            if r.status_code == 200:
                try:
                    # Yanıt JSON içindeki HTML
                    js = r.json()
                    html = js.get('data', {}).get('html', '')
                    
                    # Regex ile linkleri sök
                    items = []
                    matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html, re.DOTALL)
                    for link, title in matches:
                        full_link = link if link.startswith("http") else f"{self.domain}{link}"
                        items.append({"title": title.strip(), "url": full_link})
                    return items
                except: pass
        except Exception as e:
            print(f"    Kategori hatası: {e}")
        return []

    def resolve_video(self, url):
        """Video sayfasındaki şifreyi çözer (Deep Crawl)"""
        try:
            r = self.session.get(url, timeout=10)
            # Şifreli JSON'u bul
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            if match:
                json_str = match.group(1).replace('&quot;', '"')
                data = json.loads(json_str)
                
                decrypted = self.crypto.decrypt(data['salt'], data['iv'], data['ciphertext'])
                if decrypted:
                    # İframe linkini al
                    ifr_match = re.search(r'src="([^"]+)"', decrypted)
                    if ifr_match:
                        ifr_url = ifr_match.group(1)
                        if not ifr_url.startswith("http"): ifr_url = self.domain + ifr_url
                        
                        # İframe'e git
                        r2 = self.session.get(ifr_url, headers={"Referer": self.domain}, timeout=10)
                        
                        # .m3u8 veya .mp4 bul
                        vid_match = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', r2.text)
                        if vid_match: return vid_match.group(1)
                        
                        # Alternatif kaynak
                        src_match = re.search(r'source:\s*["\']([^"\']+)["\']', r2.text)
                        if src_match: return src_match.group(1)
        except:
            pass
        return None

def worker(crawler, item, category):
    try:
        # Rastgele bekleme yok, olabildiğince hızlı
        link = crawler.resolve_video(item['url'])
        if link and link.startswith("http"):
            return (
                f'#EXTINF:-1 group-title="{category}",{item["title"]}\n'
                f'#EXTVLCOPT:http-user-agent={crawler.session.headers["User-Agent"]}\n'
                f'#EXTVLCOPT:http-referrer={crawler.domain}/\n'
                f'{link}\n'
            )
    except:
        pass
    return None

def main():
    print("--- DiziPal Ultimate Sync ---")
    
    # AŞAMA 1: GÜVENLİ GİRİŞ (Browser)
    auth = AuthManager()
    if not auth.get_auth_data():
        print("[FATAL] Giriş yapılamadı. Github IP'si banlanmış olabilir.")
        sys.exit(1)
        
    # AŞAMA 2: HIZLI TARAMA (API)
    print("[-] Oturum bilgileri API istemcisine aktarılıyor...")
    crawler = FastCrawler(auth)
    
    playlist = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for cat in CATEGORIES:
            print(f"[-] Kategori taranıyor: {cat['name']}")
            items = crawler.get_category_items(cat['id'])
            print(f"    {len(items)} içerik bulundu.")
            
            for item in items:
                futures.append(executor.submit(worker, crawler, item, cat['name']))
        
        print(f"[-] {len(futures)} içerik için video linkleri çözülüyor...")
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.append(res)
            completed += 1
            if completed % 20 == 0: print(f"    İlerleme: {completed}/{len(futures)}")

    # KAYDET
    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for p in playlist:
                f.write(p)
        print(f"[BAŞARILI] {len(playlist)} içerik {OUTPUT_FILE} dosyasına yazıldı.")
    else:
        print("[UYARI] Liste boş.")

if __name__ == "__main__":
    main()
