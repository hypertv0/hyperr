from curl_cffi import requests
from bs4 import BeautifulSoup # Jsoup'un Python karşılığı
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import sys
import time

# --- AYARLAR ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
# Eğer Github'dan çekemezse varsayılan:
DEFAULT_DOMAIN = "https://dizipal1515.com" 
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 15

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
        # Eklenti Firefox kullanıyor ama curl_cffi'de en iyi bypass Chrome ile sağlanır.
        # Impersonate: Gerçek bir tarayıcı gibi davranır (TLS Client Hello)
        self.session = requests.Session(impersonate="chrome124")
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        })
        self.crypto = CryptoUtils()
        self.domain = self.find_domain()
        self.cKey = None
        self.cValue = None

    def find_domain(self):
        print("[-] Domain listesi kontrol ediliyor...")
        try:
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

    def init_session(self):
        """
        Smali: DiziPalOrijinal.kt -> initSession
        Jsoup kullanarak input[name=cKey] ve input[name=cValue] değerlerini çeker.
        """
        print(f"[-] Siteye giriş yapılıyor: {self.domain}")
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                r = self.session.get(self.domain, timeout=20)
                
                # Sayfa içeriğini Jsoup gibi parse et
                soup = BeautifulSoup(r.text, 'html.parser')
                page_title = soup.title.string if soup.title else "No Title"

                # Cloudflare kontrolü
                if "Just a moment" in page_title or "Cloudflare" in r.text:
                    print(f"[UYARI] Cloudflare engeli ({attempt+1}/{max_retries}). Bekleniyor...")
                    time.sleep(3)
                    continue

                # Inputları bul
                input_ckey = soup.find("input", {"name": "cKey"})
                input_cvalue = soup.find("input", {"name": "cValue"})

                if input_ckey and input_cvalue:
                    self.cKey = input_ckey.get("value")
                    self.cValue = input_cvalue.get("value")
                    print(f"[OK] Tokenlar başarıyla alındı (Jsoup Mantığı).")
                    return True
                else:
                    # Debug için sayfa başlığını yazdıralım
                    print(f"[HATA] Token inputları bulunamadı. Sayfa Başlığı: {page_title}")
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
                    html_content = js.get('data', {}).get('html', '')
                    
                    # Gelen HTML fragmentini parse et
                    soup = BeautifulSoup(html_content, 'html.parser')
                    items = []
                    
                    # Smali: div.overflow-auto a
                    # HTML yapısı: <a href="..."> ... <div class="text-white text-sm">TITLE</div> ... </a>
                    links = soup.find_all('a')
                    
                    for link in links:
                        href = link.get('href')
                        # Başlık genellikle linkin içindeki bir div'dedir
                        title_div = link.find('div', class_=lambda x: x and 'text-white' in x)
                        title = title_div.text.strip() if title_div else "Bilinmeyen Dizi"
                        
                        if href:
                            full_link = href if href.startswith("http") else f"{self.domain}{href}"
                            items.append({"title": title, "url": full_link})
                    
                    return items
                except Exception as e:
                    print(f"[!] JSON/HTML Parse hatası: {e}")
        except:
            pass
        return []

    def get_video_source(self, url):
        try:
            r = self.session.get(url, timeout=15)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            # Smali: data-rm-k özniteliğini arar
            # <div id="..." data-rm-k='{"salt":...}'></div>
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
                        # İframe linkini bul
                        # Genellikle: <iframe src="https://..." ...
                        dec_soup = BeautifulSoup(decrypted, 'html.parser')
                        iframe = dec_soup.find('iframe')
                        if iframe:
                            return self.resolve_iframe(iframe.get('src'))
        except:
            pass
        return None

    def resolve_iframe(self, iframe_url):
        try:
            if not iframe_url.startswith("http"):
                iframe_url = f"{self.domain}{iframe_url}"
            
            r = self.session.get(iframe_url, headers={"Referer": self.domain}, timeout=15)
            
            # Regex ile dosya linkini bul (Bu kısım genelde standarttır)
            match = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4))["\']', r.text)
            if match: return match.group(1)
            
            match_source = re.search(r'source:\s*["\']([^"\']+)["\']', r.text)
            if match_source: return match_source.group(1)
            
        except:
            pass
        return None

def worker(scraper, item, category):
    try:
        link = scraper.get_video_source(item['url'])
        if link and link.startswith("http"):
            entry = f'#EXTINF:-1 group-title="{category}",{item["title"]}\n'
            entry += f'#EXTVLCOPT:http-user-agent=Mozilla/5.0\n'
            entry += f'#EXTVLCOPT:http-referrer={scraper.domain}/\n'
            entry += f'{link}\n'
            return entry
    except:
        pass
    return None

def main():
    print("--- DiziPal Sync V3 (BeautifulSoup Modu) Başlatıldı ---")
    scraper = DiziScraper()
    
    # Session başlatma (cKey/cValue alma)
    if not scraper.init_session():
        print("[FATAL] Tokenlar alınamadığı için işlem durduruldu.")
        sys.exit(1)

    playlist_data = []
    
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
