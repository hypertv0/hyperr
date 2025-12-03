import requests
import json
import re
import base64
import concurrent.futures
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import sys

# SSL Hatalarını Gizle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SABİTLER (Smali Kodlarından Alındı) ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1512.com"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0"

# Kategori ID'leri (Smali kodundaki mainPageOf kısmından)
CATEGORIES = [
    {"id": "0", "name": "Yeni Eklenen Bölümler"},
    {"id": "1", "name": "Exxen Dizileri"},
    {"id": "6", "name": "Disney+ Dizileri"},
    {"id": "10", "name": "Netflix Dizileri"},
    {"id": "53", "name": "Amazon Dizileri"},
    {"id": "54", "name": "Apple TV+ Dizileri"},
    {"id": "66", "name": "Max Dizileri"},
    {"id": "181", "name": "TOD Dizileri"},
    {"id": "242", "name": "Tabii Dizileri"}
]

OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 10 # Siteyi yormamak için çok yüksek tutmuyoruz

class DiziPalCrypto:
    """Smali: DiziPalOrijinalKt.decrypt fonksiyonunun Python karşılığı"""
    def __init__(self):
        pass

    def decrypt(self, salt_hex, iv_hex, ciphertext_b64):
        try:
            # Hex stringleri byte'a çevir
            salt = bytes.fromhex(salt_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # Anahtar Türetme (PBKDF2WithHmacSHA512)
            # Android implementation uses 1000 iterations usually for this setup
            key = PBKDF2(PASSPHRASE, salt, dkLen=32, count=1000, hmac_hash_module=SHA512)
            
            # AES Deşifreleme
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            return decrypted.decode('utf-8')
        except Exception as e:
            # print(f"Decrypt Error: {e}")
            return None

class DiziPalScraper:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7"
        })
        self.crypto = DiziPalCrypto()
        self.domain = self.get_domain()
        self.cKey = None
        self.cValue = None

    def get_domain(self):
        print("[-] Domain listesi çekiliyor...")
        try:
            r = requests.get(DOMAIN_LIST_URL, timeout=10)
            if r.status_code == 200:
                # Örnek veri: DiziPalOrijinal: https://dizipal1512.com | Diger: ...
                content = r.text
                parts = content.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        domain = part.split(':', 1)[1].strip()
                        print(f"[+] Güncel Domain: {domain}")
                        return domain.rstrip('/')
        except:
            pass
        print(f"[!] Domain bulunamadı, varsayılan kullanılıyor: {DEFAULT_DOMAIN}")
        return DEFAULT_DOMAIN

    def init_session(self):
        """Ana sayfaya gidip CSRF tokenları (cKey, cValue) ve Cookie alır."""
        print("[-] Oturum başlatılıyor...")
        try:
            r = self.session.get(self.domain, timeout=15, verify=False)
            if r.status_code == 200:
                # HTML içinden cKey ve cValue bul
                # Smali: input[name=cKey] ve input[name=cValue]
                ckey_match = re.search(r'name="cKey" value="([^"]+)"', r.text)
                cvalue_match = re.search(r'name="cValue" value="([^"]+)"', r.text)
                
                if ckey_match and cvalue_match:
                    self.cKey = ckey_match.group(1)
                    self.cValue = cvalue_match.group(1)
                    print(f"[+] Tokenlar alındı. cKey: {self.cKey[:5]}...")
                    return True
        except Exception as e:
            print(f"[!] Oturum hatası: {e}")
        return False

    def fetch_category_items(self, cat_id):
        """Kategorideki dizileri çeker."""
        if not self.cKey or not self.cValue: return []
        
        url = f"{self.domain}/bg/getserielistbychannel"
        # Smali'deki POST payload yapısı
        payload = {
            "cKey": self.cKey,
            "cValue": self.cValue,
            "curPage": "1", # Şimdilik sadece ilk sayfa
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        
        try:
            r = self.session.post(url, data=payload, timeout=15, verify=False)
            if r.status_code == 200:
                # Gelen veri JSON içinde HTML barındırır
                json_data = r.json()
                html_content = json_data.get('data', {}).get('html', '')
                
                # HTML içinden linkleri regex ile çıkar
                # <a href="https://..." class="text block"...
                items = []
                matches = re.findall(r'href="([^"]+)" class="text block".*?<div class="text-white text-sm">([^<]+)</div>', html_content, re.DOTALL)
                
                for href, title in matches:
                    items.append({
                        "title": title.strip(),
                        "url": href if href.startswith("http") else f"{self.domain}{href}"
                    })
                return items
        except Exception as e:
            # print(f"Kategori çekme hatası: {e}")
            pass
        return []

    def extract_stream_link(self, url):
        """Video sayfasındaki şifreli veriyi çözer."""
        try:
            r = self.session.get(url, timeout=10, verify=False)
            if r.status_code != 200: return None
            
            # Şifreli veriyi bul: div[data-rm-k]
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            if not match:
                # Bazen JSON doğrudan script içinde olabilir
                match = re.search(r'data-rm-k>([^<]+)<', r.text)
            
            if match:
                encrypted_json_str = match.group(1)
                data = json.loads(encrypted_json_str)
                
                ciphertext = data.get('ciphertext')
                iv = data.get('iv')
                salt = data.get('salt')
                
                if ciphertext and iv and salt:
                    decrypted_url = self.crypto.decrypt(salt, iv, ciphertext)
                    if decrypted_url:
                        # Decrypted URL genellikle bir iframe linkidir (player)
                        # Direkt bu linki veya içindeki m3u8'i alabiliriz.
                        # M3U için iframe URL'si genelde yeterlidir (oynatıcı destekliyorsa)
                        # Ama biz bir adım ileri gidip içindeki mp4/m3u8'i regex ile arayalım.
                        return self.resolve_player_link(decrypted_url)
        except:
            pass
        return None

    def resolve_player_link(self, player_url):
        """Iframe içindeki gerçek videoyu bulmaya çalışır."""
        try:
            # URL domain kontrolü
            if not player_url.startswith("http"):
                player_url = f"{self.domain}{player_url}"

            r = self.session.get(player_url, headers={"Referer": self.domain}, timeout=10, verify=False)
            
            # M3U8 veya MP4 ara
            # Genelde: file: "https://....m3u8"
            video_match = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4))["\']', r.text)
            if video_match:
                return video_match.group(1)
            
            # Eğer bulamazsa player URL'sini döndür (Bazı IPTV playerlar webview ile açabilir)
            return player_url
        except:
            return player_url

def process_item(scraper, item, category_name):
    final_link = scraper.extract_stream_link(item['url'])
    if final_link:
        # M3U Entry
        return (
            f'#EXTINF:-1 group-title="{category_name}",{item["title"]}\n'
            f'#EXTVLCOPT:http-user-agent={USER_AGENT}\n'
            f'#EXTVLCOPT:http-referrer={scraper.domain}/\n'
            f'{final_link}\n'
        )
    return None

def main():
    print("--- DiziPal M3U Oluşturucu ---")
    scraper = DiziPalScraper()
    
    if not scraper.init_session():
        print("[FATAL] Siteye giriş yapılamadı (Cloudflare veya bakım).")
        sys.exit(1)

    playlist_entries = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        
        for cat in CATEGORIES:
            print(f"[-] Kategori taranıyor: {cat['name']}")
            items = scraper.fetch_category_items(cat['id'])
            print(f"    Bulunan içerik: {len(items)}")
            
            for item in items:
                futures.append(executor.submit(process_item, scraper, item, cat['name']))
        
        print("[-] Linkler çözülüyor (Bu işlem biraz sürebilir)...")
        for i, f in enumerate(concurrent.futures.as_completed(futures)):
            res = f.result()
            if res: playlist_entries.append(res)
            if i % 20 == 0: print(f"    İşlenen: {i}")

    if playlist_entries:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist_entries:
                f.write(entry)
        print(f"[BAŞARILI] {len(playlist_entries)} içerik {OUTPUT_FILE} dosyasına kaydedildi.")
    else:
        print("[UYARI] Hiçbir link bulunamadı.")

if __name__ == "__main__":
    main()
