from curl_cffi import requests
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

# --- AYARLAR (SMALI KODUNDAN BİREBİR) ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 5 # Cloudflare tetiklenmemesi için worker sayısını düşürdük

# Smali kodundaki User-Agent (Satır 112)
# Bu UA, sunucunun "Bu uygulama trafiği" diyip geçiş izni vermesini sağlar.
APP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

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

class DiziScraper:
    def __init__(self):
        # Cloudflare'i aşmak için "firefox110" parmak izini kullanıyoruz ancak 
        # User-Agent'ı uygulamanınkiyle değiştiriyoruz.
        self.session = requests.Session(impersonate="firefox110")
        self.session.headers.update({
            "User-Agent": APP_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1"
        })
        self.crypto = CryptoUtils()
        self.domain = self.find_domain()
        self.cKey = None
        self.cValue = None

    def find_domain(self):
        print("[-] Domain listesi kontrol ediliyor...")
        try:
            # Github isteği standart requests ile yapılabilir
            import requests as std_requests
            r = std_requests.get(DOMAIN_LIST_URL, timeout=10)
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

    def init_session(self):
        print(f"[-] Siteye giriş yapılıyor: {self.domain}")
        
        # İlk istekte referer olmamalı
        if "Referer" in self.session.headers:
            del self.session.headers["Referer"]

        max_retries = 5
        for attempt in range(max_retries):
            try:
                # Rastgele bekleme (Anti-bot tespiti için)
                time.sleep(random.uniform(1, 3))
                
                r = self.session.get(self.domain, timeout=30)
                
                # Cloudflare Kontrolü
                if r.status_code == 403 or r.status_code == 503 or "Just a moment" in r.text:
                    print(f"[UYARI] Cloudflare engeli ({attempt+1}/{max_retries}). Tekrar deneniyor...")
                    continue

                soup = BeautifulSoup(r.text, 'html.parser')
                
                # Tokenları Bul
                input_ckey = soup.find("input", {"name": "cKey"})
                input_cvalue = soup.find("input", {"name": "cValue"})

                if input_ckey and input_cvalue:
                    self.cKey = input_ckey.get("value")
                    self.cValue = input_cvalue.get("value")
                    print(f"[OK] Giriş başarılı. Tokenlar alındı.")
                    
                    # Sonraki istekler için Referer ve Origin ayarla (Smali ile aynı)
                    self.session.headers.update({
                        "Referer": f"{self.domain}/",
                        "Origin": self.domain,
                        "X-Requested-With": "XMLHttpRequest"
                    })
                    return True
                else:
                    # Belki site açıldı ama inputlar yok?
                    print(f"[HATA] Site açıldı fakat tokenlar bulunamadı. Başlık: {soup.title.string if soup.title else 'Yok'}")
                    # Debug için HTML'in küçük bir kısmını yazdır
                    # print(r.text[:500])
            except Exception as e:
                print(f"[HATA] Bağlantı sorunu: {e}")
            
        return False

    def get_category_content(self, cat_id):
        if not self.cKey: return []
        
        url = f"{self.domain}/bg/getserielistbychannel"
        data = {
            "cKey": self.cKey,
            "cValue": self.cValue,
            "curPage": "1",
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        
        try:
            # POST isteği
            r = self.session.post(url, data=data, timeout=20)
            if r.status_code == 200:
                try:
                    js = r.json()
                    html_content = js.get('data', {}).get('html', '')
                    soup = BeautifulSoup(html_content, 'html.parser')
                    items = []
                    
                    # Linkleri topla
                    links = soup.find_all('a')
                    for link in links:
                        href = link.get('href')
                        # Başlık extraction
                        title_div = link.find('div', class_=lambda x: x and 'text-white' in x)
                        title = title_div.text.strip() if title_div else link.get('title', "Bilinmeyen Dizi")
                        
                        if href:
                            full_link = href if href.startswith("http") else f"{self.domain}{href}"
                            items.append({"title": title, "url": full_link})
                    
                    return items
                except:
                    pass
        except:
            pass
        return []

    def get_video_source(self, url):
        try:
            # Detay sayfasına git
            r = self.session.get(url, timeout=15)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            div_encrypted = soup.find('div', attrs={'data-rm-k': True})
            
            if div_encrypted:
                json_str = div_encrypted['data-rm-k']
                data = json.loads(json_str)
                
                salt = data.get('salt')
                iv = data.get('iv')
                ciphertext = data.get('ciphertext')

                if salt and iv and ciphertext:
                    decrypted = self.crypto.decrypt(salt, iv, ciphertext)
                    if decrypted:
                        # iframe src'sini bul
                        match = re.search(r'src="([^"]+)"', decrypted)
                        if match:
                            return self.resolve_iframe(match.group(1))
        except:
            pass
        return None

    def resolve_iframe(self, iframe_url):
        try:
            if not iframe_url.startswith("http"):
                iframe_url = f"{self.domain}{iframe_url}"
            
            # İframe sayfasına git
            r = self.session.get(iframe_url, headers={"Referer": self.domain}, timeout=15)
            
            # .m3u8 linkini ara
            match = re.search(r'file:\s*["\']([^"\']+\.m3u8[^"\']*)["\']', r.text)
            if match: return match.group(1)
            
            # .mp4 linkini ara
            match = re.search(r'file:\s*["\']([^"\']+\.mp4[^"\']*)["\']', r.text)
            if match: return match.group(1)

            # 'source' değişkenini ara
            match = re.search(r'source:\s*["\']([^"\']+)["\']', r.text)
            if match: return match.group(1)
            
        except:
            pass
        return None

def worker(scraper, item, category):
    # Her istekte ufak gecikme (WAF bypass için)
    time.sleep(random.uniform(0.5, 2.0))
    
    link = scraper.get_video_source(item['url'])
    if link and link.startswith("http"):
        return (
            f'#EXTINF:-1 group-title="{category}",{item["title"]}\n'
            f'#EXTVLCOPT:http-user-agent={APP_USER_AGENT}\n'
            f'#EXTVLCOPT:http-referrer={scraper.domain}/\n'
            f'{link}\n'
        )
    return None

def main():
    print("--- DiziPal Sync V4 (Full Stealth) ---")
    scraper = DiziScraper()
    
    if not scraper.init_session():
        print("[FATAL] Tüm denemelere rağmen siteye girilemedi.")
        sys.exit(1)

    playlist_data = []
    
    # Worker sayısını düşürdük çünkü çok hızlı istek Cloudflare'i tetikler
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        
        for cat in CATEGORIES:
            print(f"[-] Kategori taranıyor: {cat['name']}")
            items = scraper.get_category_content(cat['id'])
            
            if not items:
                print("    (İçerik bulunamadı veya erişim engellendi)")
                continue
                
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
            if completed % 5 == 0:
                print(f"    İlerleme: {completed}/{len(futures)}")

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
