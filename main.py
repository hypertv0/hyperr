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
import requests

# --- AYARLAR ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 20  # Aynı anda kaç sayfa taranacak

# Eklentideki Kategoriler
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
    def decrypt(self, salt_hex, iv_hex, ciphertext_b64):
        try:
            salt = bytes.fromhex(salt_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = base64.b64decode(ciphertext_b64)
            key = PBKDF2(PASSPHRASE, salt, dkLen=32, count=1000, hmac_hash_module=SHA512)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode('utf-8')
        except:
            return None

class AuthManager:
    """Cloudflare'i geçer ve API anahtarlarını çalar"""
    def __init__(self):
        self.domain = self._get_domain()
        self.cookies = {}
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        self.cKey = None
        self.cValue = None

    def _get_domain(self):
        try:
            r = requests.get(DOMAIN_LIST_URL, timeout=5)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        d = part.split(':', 1)[1].strip().rstrip('/')
                        print(f"[INFO] Domain: {d}")
                        return d
        except: pass
        return DEFAULT_DOMAIN

    def login(self):
        print("[-] Tarayıcı başlatılıyor (Giriş İşlemi)...")
        
        co = ChromiumOptions()
        co.set_argument('--no-sandbox')
        co.set_argument('--disable-gpu')
        co.set_argument('--headless=new') # Xvfb ile çalışacağı için headless
        co.set_user_agent(self.ua)
        
        page = ChromiumPage(co)
        
        try:
            print(f"[-] Siteye gidiliyor: {self.domain}")
            page.get(self.domain)
            
            # Cloudflare Turnstile kontrolü
            if page.ele('@id=challenge-stage', timeout=3):
                 print("[-] Cloudflare Challenge algılandı, tıklanıyor...")
                 page.uc_gui_click_captcha()
                 time.sleep(5)
            
            print("[-] Sayfa elementleri bekleniyor...")
            # HATA DÜZELTME: wait.ele yerine doğrudan ele() ve timeout kullanıyoruz
            # cKey inputunun yüklenmesini bekle
            if page.ele('css:input[name="cKey"]', timeout=30):
                self.cKey = page.ele('css:input[name="cKey"]').attr('value')
                self.cValue = page.ele('css:input[name="cValue"]').attr('value')
                
                # Cookie al
                for c in page.cookies.as_dict():
                    self.cookies[c['name']] = c['value']
                
                self.ua = page.user_agent
                print(f"[OK] Giriş Başarılı. Token: {self.cKey[:5]}...")
                return True
            else:
                print("[FATAL] 30 saniye beklendi, token inputları bulunamadı.")
                # Sayfa kaynağını kontrol et (Debug)
                # print(page.html[:500])
                return False
                
        except Exception as e:
            print(f"[FATAL] Tarayıcı hatası: {e}")
            return False
        finally:
            page.quit()

class Crawler:
    def __init__(self, manager):
        self.manager = manager
        self.crypto = CryptoUtils()
        # API istekleri için curl_cffi session
        self.session = crequests.Session(impersonate="chrome120")
        self.session.cookies.update(manager.cookies)
        self.session.headers.update({
            "User-Agent": manager.ua,
            "Referer": f"{manager.domain}/",
            "Origin": manager.domain,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "*/*"
        })

    def get_page_items(self, cat_id, page_num):
        """Belirli bir kategorinin belirli bir sayfasını çeker"""
        url = f"{self.manager.domain}/bg/getserielistbychannel"
        data = {
            "cKey": self.manager.cKey,
            "cValue": self.manager.cValue,
            "curPage": str(page_num),
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        
        items = []
        try:
            r = self.session.post(url, data=data, timeout=15)
            if r.status_code == 200:
                try:
                    js = r.json()
                    html = js.get('data', {}).get('html', '')
                    # İçerik yoksa (sayfa sonu) boş döner
                    if not html.strip(): return []
                    
                    matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html, re.DOTALL)
                    for href, title in matches:
                        full_url = href if href.startswith("http") else f"{self.manager.domain}{href}"
                        items.append((title.strip(), full_url))
                except: pass
        except Exception as e:
            # print(f"Sayfa hatası: {e}")
            pass
        return items

    def resolve_video(self, title, url, category):
        """Video linkini çözer"""
        try:
            r = self.session.get(url, timeout=10)
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            
            if match:
                json_str = match.group(1).replace('&quot;', '"')
                data = json.loads(json_str)
                decrypted = self.crypto.decrypt(data['salt'], data['iv'], data['ciphertext'])
                
                if decrypted:
                    src_match = re.search(r'src="([^"]+)"', decrypted)
                    if src_match:
                        iframe_url = src_match.group(1)
                        if not iframe_url.startswith("http"): 
                            iframe_url = self.manager.domain + iframe_url
                        
                        r_ifr = self.session.get(iframe_url, headers={"Referer": self.manager.domain}, timeout=10)
                        
                        # M3U8
                        vid_match = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', r_ifr.text)
                        if vid_match:
                            final_url = vid_match.group(1)
                            return (
                                f'#EXTINF:-1 group-title="{category}",{title}\n'
                                f'#EXTVLCOPT:http-user-agent={self.manager.ua}\n'
                                f'#EXTVLCOPT:http-referrer={self.manager.domain}/\n'
                                f'{final_url}\n'
                            )
        except:
            pass
        return None

def worker_category(crawler, cat):
    """Bir kategoriyi sonuna kadar tarar"""
    cat_items = []
    page = 1
    max_pages = 50 # Sonsuz döngü koruması
    
    print(f"[-] Kategori Başladı: {cat['name']}")
    
    while page <= max_pages:
        items = crawler.get_page_items(cat['id'], page)
        if not items:
            break # İçerik bitti
            
        print(f"    > {cat['name']} - Sayfa {page} ({len(items)} içerik)")
        cat_items.extend(items)
        page += 1
        time.sleep(0.5) # API'yi boğmamak için
        
    return cat_items, cat['name']

def main():
    print("--- DiziPal API Scraper V8 ---")
    mgr = AuthManager()
    
    if not mgr.login():
        sys.exit(1)

    crawler = Crawler(mgr)
    all_content_links = [] # (title, url, category_name)
    
    # 1. ADIM: Tüm sayfaları gez ve linkleri topla
    # Bu işlem hızlıdır çünkü sadece link listesi çeker, video çözmez.
    print("[-] Tüm kategoriler taranıyor...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker_category, crawler, cat) for cat in CATEGORIES]
        
        for f in concurrent.futures.as_completed(futures):
            items, cat_name = f.result()
            for title, url in items:
                all_content_links.append((title, url, cat_name))

    # Tekilleştirme
    all_content_links = list(set(all_content_links))
    print(f"[OK] Toplam {len(all_content_links)} adet içerik bulundu. Linkler çözülüyor...")

    # 2. ADIM: Linkleri Çöz (Video URL'lerini al)
    playlist = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Yükü karıştır
        random.shuffle(all_content_links)
        
        futures = []
        for title, url, cat_name in all_content_links:
            futures.append(executor.submit(crawler.resolve_video, title, url, cat_name))
            
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.append(res)
            completed += 1
            if completed % 50 == 0:
                print(f"    İlerleme: {completed}/{len(all_content_links)}")

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist:
                f.write(entry)
        print(f"[BAŞARILI] {len(playlist)} içerik kaydedildi.")
    else:
        print("[HATA] Liste oluşturulamadı.")

if __name__ == "__main__":
    main()
