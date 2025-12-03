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
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 15

# Uygulamanın Kategori Listesi (InatBox Plugin'den alındı)
CATEGORIES = [
    {"id": "0", "name": "Yeni Eklenen Bölümler"},
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
    """Şifre Çözücü"""
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

class SessionManager:
    def __init__(self):
        self.domain = self._get_domain()
        self.cookies = {}
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        self.cKey = None
        self.cValue = None

    def _get_domain(self):
        try:
            r = crequests.get(DOMAIN_LIST_URL, timeout=5, impersonate="chrome120")
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        return part.split(':', 1)[1].strip().rstrip('/')
        except: pass
        return DEFAULT_DOMAIN

    def login(self):
        """Cloudflare'i geçip API anahtarlarını (cKey, cValue) alır"""
        print("[-] Tarayıcı başlatılıyor (DrissionPage)...")
        
        co = ChromiumOptions()
        co.set_argument('--no-sandbox')
        co.set_argument('--disable-gpu')
        # Xvfb kullandığımız için headless=False yapabiliriz (Daha güvenli)
        # Ama DrissionPage headless=new modunda da çok iyidir.
        co.set_argument('--headless=new') 
        co.set_user_agent(self.ua)
        
        page = ChromiumPage(co)
        
        try:
            print(f"[-] {self.domain} adresine gidiliyor...")
            page.get(self.domain)
            
            # Cloudflare kontrolü
            if page.ele('@id=challenge-stage', timeout=3):
                 print("[-] Cloudflare Challenge algılandı, çözülüyor...")
                 page.uc_gui_click_captcha()
                 time.sleep(5)
            
            # Sitenin yüklenmesini ve inputların gelmesini bekle
            print("[-] Site yükleniyor ve tokenlar aranıyor...")
            # 45 saniye bekle
            ele = page.wait.ele('css:input[name="cKey"]', timeout=45)
            
            if ele:
                self.cKey = page.ele('css:input[name="cKey"]').attr('value')
                self.cValue = page.ele('css:input[name="cValue"]').attr('value')
                
                # Çerezleri al
                for c in page.cookies.as_dict():
                    self.cookies[c['name']] = c['value']
                
                self.ua = page.user_agent
                print(f"[OK] Giriş Başarılı. Token: {self.cKey[:5]}...")
                return True
            else:
                print("[FATAL] Site açıldı ama 'cKey' bulunamadı.")
                print(f"Sayfa Başlığı: {page.title}")
                return False
                
        except Exception as e:
            print(f"[FATAL] Tarayıcı hatası: {e}")
            return False
        finally:
            page.quit()

class APICrawler:
    def __init__(self, manager):
        self.manager = manager
        self.crypto = CryptoUtils()
        self.session = crequests.Session(impersonate="chrome120")
        self.session.cookies.update(manager.cookies)
        self.session.headers.update({
            "User-Agent": manager.ua,
            "Referer": manager.domain,
            "Origin": manager.domain,
            "X-Requested-With": "XMLHttpRequest" # API için şart
        })

    def fetch_category(self, cat_id):
        """API'den kategori içeriğini çeker"""
        url = f"{self.manager.domain}/bg/getserielistbychannel"
        data = {
            "cKey": self.manager.cKey,
            "cValue": self.manager.cValue,
            "curPage": "1",
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        
        items = []
        try:
            r = self.session.post(url, data=data, timeout=20)
            if r.status_code == 200:
                try:
                    js = r.json()
                    html = js.get('data', {}).get('html', '')
                    # Regex ile linkleri ve başlıkları sök
                    matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html, re.DOTALL)
                    for href, title in matches:
                        full_url = href if href.startswith("http") else f"{self.manager.domain}{href}"
                        items.append((title.strip(), full_url))
                except: pass
        except Exception as e:
            print(f"[!] API Hatası ({cat_id}): {e}")
            
        return items

    def resolve_link(self, title, url, category):
        """Video sayfasındaki şifreyi çözer"""
        try:
            r = self.session.get(url, timeout=10)
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            
            if match:
                json_str = match.group(1).replace('&quot;', '"')
                data = json.loads(json_str)
                decrypted = self.crypto.decrypt(data['salt'], data['iv'], data['ciphertext'])
                
                if decrypted:
                    # İframe bul
                    src_match = re.search(r'src="([^"]+)"', decrypted)
                    if src_match:
                        iframe_url = src_match.group(1)
                        if not iframe_url.startswith("http"): 
                            iframe_url = self.manager.domain + iframe_url
                        
                        # İframe içine girip .m3u8 ara
                        r_ifr = self.session.get(iframe_url, headers={"Referer": self.manager.domain}, timeout=10)
                        
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

def main():
    print("--- DiziPal API Sync ---")
    
    mgr = SessionManager()
    
    # 1. Tarayıcı ile Tokenları Al
    if not mgr.login():
        sys.exit(1)
        
    crawler = APICrawler(mgr)
    playlist = []
    
    # 2. Kategorileri Tara (Multithreading)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        
        for cat in CATEGORIES:
            print(f"[-] Kategori işleniyor: {cat['name']}")
            items = crawler.fetch_category(cat['id'])
            print(f"    > {len(items)} içerik bulundu.")
            
            for title, url in items:
                futures.append(executor.submit(crawler.resolve_link, title, url, cat['name']))
        
        print(f"[-] Linkler çözülüyor ({len(futures)} adet)...")
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.append(res)
            completed += 1
            if completed % 20 == 0: print(f"    İlerleme: {completed}/{len(futures)}")

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist:
                f.write(entry)
        print(f"[BAŞARILI] {len(playlist)} içerik kaydedildi.")
    else:
        print("[HATA] Hiçbir link çözülemedi.")

if __name__ == "__main__":
    main()
