from DrissionPage import ChromiumPage, ChromiumOptions
from curl_cffi import requests as crequests
from bs4 import BeautifulSoup
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
import xml.etree.ElementTree as ET

# --- AYARLAR ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 15

# API için Kategori Listesi (Plan B)
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

class DiziManager:
    def __init__(self):
        self.domain = self._get_domain()
        self.cookies = {}
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        self.cKey = None
        self.cValue = None
        self.sitemap_content = None # Tarayıcıdan alınan XML verisi

    def _get_domain(self):
        try:
            r = crequests.get(DOMAIN_LIST_URL, timeout=5, impersonate="chrome120")
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        d = part.split(':', 1)[1].strip().rstrip('/')
                        print(f"[INFO] Domain: {d}")
                        return d
        except: pass
        return DEFAULT_DOMAIN

    def login_and_fetch_sitemap(self):
        """Tarayıcı ile girer, tokenları alır ve sitemap'i okur"""
        print("[-] Tarayıcı başlatılıyor (DrissionPage)...")
        
        co = ChromiumOptions()
        co.set_argument('--no-sandbox')
        co.set_argument('--disable-gpu')
        co.set_argument('--headless=new') 
        co.set_user_agent(self.ua)
        
        page = ChromiumPage(co)
        
        try:
            # 1. Ana Sayfaya Git
            print(f"[-] {self.domain} adresine gidiliyor...")
            page.get(self.domain)
            
            if page.ele('@id=challenge-stage', timeout=2):
                 print("[-] Cloudflare Challenge algılandı, çözülüyor...")
                 page.uc_gui_click_captcha()
                 time.sleep(5)
            
            # Sayfanın yüklenmesini bekle
            page.wait.ele('body', timeout=30)
            
            # Tokenları topla (API Modu için gerekli)
            try:
                self.cKey = page.ele('css:input[name="cKey"]').attr('value')
                self.cValue = page.ele('css:input[name="cValue"]').attr('value')
                print(f"[OK] Tokenlar alındı: {self.cKey[:5]}...")
            except:
                print("[UYARI] Tokenlar sayfada bulunamadı (Sitemap modu denenecek).")

            # Çerezleri al
            self.cookies = {c['name']: c['value'] for c in page.cookies.as_dict()}
            self.ua = page.user_agent
            
            # 2. Sitemap'i TARAYICI İÇİNDEN oku (Requests ile değil!)
            print("[-] Tarayıcı üzerinden Sitemap okunuyor...")
            try:
                page.get(f"{self.domain}/sitemap.xml")
                if "xml" in page.html or "urlset" in page.html:
                    self.sitemap_content = page.html
                    print("[OK] Sitemap verisi tarayıcıdan alındı.")
                else:
                    print("[!] Sitemap tarayıcıda görüntülenemedi.")
            except Exception as e:
                print(f"[!] Sitemap erişim hatası: {e}")

            return True

        except Exception as e:
            print(f"[FATAL] Tarayıcı hatası: {e}")
            return False
        finally:
            page.quit()

class Crawler:
    def __init__(self, manager):
        self.manager = manager
        self.crypto = CryptoUtils()
        self.session = crequests.Session(impersonate="chrome120")
        self.session.cookies.update(manager.cookies)
        self.session.headers.update({
            "User-Agent": manager.ua,
            "Referer": manager.domain,
            "Origin": manager.domain
        })

    def parse_sitemap(self):
        """Sitemap içeriğini parse eder"""
        links = []
        if not self.manager.sitemap_content: return []
        
        try:
            # XML bazen HTML içine gömülü gelebilir, temizle
            xml_content = self.manager.sitemap_content
            if "<body" in xml_content:
                soup = BeautifulSoup(xml_content, 'lxml')
                xml_content = soup.get_text()

            root = ET.fromstring(xml_content)
            for child in root:
                for elem in child:
                    if "loc" in elem.tag:
                        url = elem.text
                        if url and ("/dizi/" in url or "/film/" in url or "/bolum/" in url):
                            links.append(url)
            
            # Alt sitemap kontrolü (sitemap_index)
            # Basitlik adına, eğer linklerde .xml varsa onları da çekmemiz gerekir ama
            # DiziPal genelde tek sitemap veya index kullanır. Şimdilik direkt linkleri alıyoruz.
            
        except Exception as e:
            print(f"[!] XML Parse hatası: {e}")
            # Fallback olarak regex
            links = re.findall(r'<loc>(.*?)</loc>', self.manager.sitemap_content)
            
        return list(set(links))

    def fetch_from_api(self, cat_id):
        """Sitemap çalışmazsa API'den çeker (Plan B)"""
        url = f"{self.manager.domain}/bg/getserielistbychannel"
        data = {
            "cKey": self.manager.cKey,
            "cValue": self.manager.cValue,
            "curPage": "1",
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        try:
            r = self.session.post(url, data=data, timeout=15)
            if r.status_code == 200:
                html = r.json().get('data', {}).get('html', '')
                matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html, re.DOTALL)
                return [f"{self.manager.domain}{m[0]}" if not m[0].startswith("http") else m[0] for m in matches]
        except: pass
        return []

    def process_url(self, url):
        """Tek bir URL'yi işler ve M3U satırı döndürür"""
        try:
            r = self.session.get(url, timeout=10)
            
            # Başlık bul
            title_match = re.search(r'<h1[^>]*>(.*?)</h1>', r.text)
            title = title_match.group(1).strip() if title_match else "Bilinmeyen İçerik"
            title = re.sub(r'<[^>]+>', '', title) # HTML taglerini temizle

            # Şifreli veri
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
                        
                        # Video linki bul
                        vid_match = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', r_ifr.text)
                        if vid_match:
                            final_url = vid_match.group(1)
                            cat_name = "Filmler" if "/film/" in url else "Diziler"
                            
                            return (
                                f'#EXTINF:-1 group-title="{cat_name}",{title}\n'
                                f'#EXTVLCOPT:http-user-agent={self.manager.ua}\n'
                                f'#EXTVLCOPT:http-referrer={self.manager.domain}/\n'
                                f'{final_url}\n'
                            )
        except:
            pass
        return None

def main():
    print("--- DiziPal Multi-Mode Sync ---")
    mgr = DiziManager()
    
    if not mgr.get_cookies_with_browser():
        sys.exit(1)

    crawler = Crawler(mgr)
    target_links = []

    # PLAN A: SITEMAP
    sitemap_links = crawler.parse_sitemap()
    if sitemap_links:
        print(f"[OK] Sitemap üzerinden {len(sitemap_links)} link bulundu.")
        target_links = sitemap_links
    else:
        # PLAN B: API
        print("[!] Sitemap boş, API moduna geçiliyor...")
        if mgr.cKey and mgr.cValue:
            for cat in CATEGORIES:
                print(f"    > Kategori taranıyor: {cat['name']}")
                links = crawler.fetch_from_api(cat['id'])
                target_links.extend(links)
        else:
            print("[FATAL] API Tokenları da yok. İşlem başarısız.")
            sys.exit(1)

    # Tekilleştir
    target_links = list(set(target_links))
    print(f"[-] Toplam {len(target_links)} içerik işlenecek...")

    playlist = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Yükü dağıtmak için karıştır
        random.shuffle(target_links)
        
        # Linkleri işle
        futures = [executor.submit(crawler.process_url, link) for link in target_links]
        
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.append(res)
            completed += 1
            if completed % 50 == 0:
                print(f"    İlerleme: {completed}/{len(target_links)}")

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist:
                f.write(entry)
        print(f"[BAŞARILI] {len(playlist)} içerik kaydedildi.")
    else:
        print("[UYARI] Liste oluşturulamadı.")

if __name__ == "__main__":
    main()
