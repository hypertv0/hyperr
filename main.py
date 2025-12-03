import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import requests
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
import subprocess
import os

# --- AYARLAR ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 10

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

class SessionManager:
    def __init__(self):
        self.domain = self.find_domain()
        self.cookies = {}
        self.cKey = None
        self.cValue = None
        self.user_agent = None

    def find_domain(self):
        try:
            r = requests.get(DOMAIN_LIST_URL, timeout=5)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        return part.split(':', 1)[1].strip().rstrip('/')
        except: pass
        return DEFAULT_DOMAIN

    def get_chrome_major_version(self):
        """Sistemdeki Chrome versiyonunu bulur"""
        try:
            # Linux/Ubuntu komutu
            result = subprocess.check_output(['google-chrome', '--version']).decode('utf-8')
            # Çıktı örneği: "Google Chrome 142.0.7444.175"
            version = result.strip().split()[-1].split('.')[0]
            print(f"[-] Tespit edilen Chrome Sürümü: {version}")
            return int(version)
        except Exception as e:
            print(f"[UYARI] Chrome sürümü algılanamadı ({e}), varsayılan kullanılıyor.")
            return None

    def get_tokens_via_selenium(self):
        print("[-] Selenium başlatılıyor (Anti-Detect Mod)...")
        
        # Sürüm çakışmasını önlemek için sistemdeki versiyonu al
        chrome_ver = self.get_chrome_major_version()

        options = uc.ChromeOptions()
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--window-size=1920,1080')
        
        try:
            # version_main parametresi ile sürüm çakışmasını engelliyoruz
            driver = uc.Chrome(options=options, version_main=chrome_ver)
        except Exception as e:
            print(f"[FATAL] Driver başlatılamadı: {e}")
            return False
        
        try:
            print(f"[-] Siteye gidiliyor: {self.domain}")
            driver.get(self.domain)
            
            print("[-] Cloudflare/Site yüklenmesi bekleniyor (Max 45sn)...")
            try:
                # Bekleme süresini artırdık
                WebDriverWait(driver, 45).until(
                    EC.presence_of_element_located((By.NAME, "cKey"))
                )
                print("[OK] Site başarıyla yüklendi!")
            except:
                print("[FATAL] Site yüklenemedi veya Cloudflare aşılamadı.")
                # Hata ayıklama için sayfa kaynağının başını yazdır
                print(f"Title: {driver.title}")
                return False

            # Verileri Çek
            self.cKey = driver.find_element(By.NAME, "cKey").get_attribute("value")
            self.cValue = driver.find_element(By.NAME, "cValue").get_attribute("value")
            self.user_agent = driver.execute_script("return navigator.userAgent;")
            
            selenium_cookies = driver.get_cookies()
            for cookie in selenium_cookies:
                self.cookies[cookie['name']] = cookie['value']

            print(f"[OK] Tokenlar alındı: {self.cKey[:5]}...")
            return True
            
        except Exception as e:
            print(f"[HATA] Selenium işleminde hata: {e}")
            return False
        finally:
            try:
                driver.quit()
            except:
                pass

class DiziCrawler:
    def __init__(self, session_data):
        self.domain = session_data.domain
        self.cKey = session_data.cKey
        self.cValue = session_data.cValue
        self.cookies = session_data.cookies
        self.ua = session_data.user_agent
        self.crypto = CryptoUtils()
        
        self.session = requests.Session()
        self.session.cookies.update(self.cookies)
        self.session.headers.update({
            "User-Agent": self.ua,
            "Referer": f"{self.domain}/",
            "Origin": self.domain,
            "X-Requested-With": "XMLHttpRequest"
        })

    def get_category_content(self, cat_id):
        url = f"{self.domain}/bg/getserielistbychannel"
        data = {
            "cKey": self.cKey,
            "cValue": self.cValue,
            "curPage": "1",
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        
        try:
            r = self.session.post(url, data=data, timeout=20)
            if r.status_code == 200:
                try:
                    html = r.json().get('data', {}).get('html', '')
                    items = []
                    matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html, re.DOTALL)
                    for link, title in matches:
                        full_link = link if link.startswith("http") else f"{self.domain}{link}"
                        items.append({"title": title.strip(), "url": full_link})
                    return items
                except: pass
        except: pass
        return []

    def get_video_link(self, url):
        try:
            r = self.session.get(url, timeout=10)
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            
            if match:
                data = json.loads(match.group(1).replace('&quot;', '"'))
                decrypted = self.crypto.decrypt(data['salt'], data['iv'], data['ciphertext'])
                
                if decrypted:
                    iframe_match = re.search(r'src="([^"]+)"', decrypted)
                    if iframe_match:
                        iframe_url = iframe_match.group(1)
                        if not iframe_url.startswith("http"): iframe_url = self.domain + iframe_url
                        
                        r2 = self.session.get(iframe_url, headers={"Referer": self.domain}, timeout=10)
                        
                        m3u = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', r2.text)
                        if m3u: return m3u.group(1)
                        
                        src = re.search(r'source:\s*["\']([^"\']+)["\']', r2.text)
                        if src: return src.group(1)
        except:
            pass
        return None

def worker(crawler, item, category):
    try:
        link = crawler.get_video_link(item['url'])
        if link and link.startswith("http"):
            return (
                f'#EXTINF:-1 group-title="{category}",{item["title"]}\n'
                f'#EXTVLCOPT:http-user-agent={crawler.ua}\n'
                f'#EXTVLCOPT:http-referrer={crawler.domain}/\n'
                f'{link}\n'
            )
    except:
        pass
    return None

def main():
    print("--- DiziPal Hybrid Sync V2 ---")
    
    mgr = SessionManager()
    if not mgr.get_tokens_via_selenium():
        sys.exit(1)
        
    print("[-] Tokenlar alındı, hızlı tarama başlıyor...")
    crawler = DiziCrawler(mgr)
    
    playlist = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for cat in CATEGORIES:
            print(f"    > {cat['name']} taranıyor...")
            items = crawler.get_category_content(cat['id'])
            
            for item in items:
                futures.append(executor.submit(worker, crawler, item, cat['name']))
        
        print(f"[-] {len(futures)} içerik detayları çözülüyor...")
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.append(res)
            completed += 1
            if completed % 20 == 0: print(f"    İlerleme: {completed}/{len(futures)}")

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for p in playlist:
                f.write(p)
        print(f"[BAŞARILI] {len(playlist)} içerik kaydedildi.")
    else:
        print("[UYARI] Liste boş.")

if __name__ == "__main__":
    main()
