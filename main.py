import requests as std_requests # For GitHub request
from curl_cffi import requests as crequests # For Cloudflare bypass
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
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 20

# GÖNDERDİĞİN AĞ TRAFİĞİNDEN KOPYALANAN BAŞLIKLAR (BU KISIM KRİTİK)
HEADERS = {
    'sec-ch-ua': '"Chromium";v="142", "Android WebView";v="142", "Not_A Brand";v="99"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Linux; Android 16; M2102J20SG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.171 Mobile Safari/537.36',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'x-requested-with': 'com.duckduckgo.mobile.android', # SMOKING GUN
    'sec-fetch-site': 'none',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-user': '?1',
    'sec-fetch-dest': 'document',
    'accept-encoding': 'gzip, deflate, br, zstd',
    'accept-language': 'en,tr-TR;q=0.9,tr;q=0.8,en-US;q=0.7'
}

CATEGORIES = [
    {"id": "0", "name": "Yeni Eklenenler"}, {"id": "1", "name": "Exxen"},
    {"id": "6", "name": "Disney+"}, {"id": "10", "name": "Netflix"},
    {"id": "53", "name": "Amazon"}, {"id": "54", "name": "Apple+"},
    {"id": "66", "name": "BluTV"}, {"id": "181", "name": "TOD"},
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

class DiziPalClient:
    def __init__(self):
        self.crypto = CryptoUtils()
        self.session = crequests.Session(impersonate="chrome120") # Sadece TLS parmak izi için
        self.session.headers = HEADERS # Başlıkları bizimkilerle değiştir
        
        self.domain = self._get_domain()
        self.cKey = None
        self.cValue = None

    def _get_domain(self):
        try:
            r = std_requests.get(DOMAIN_LIST_URL, timeout=5)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        d = part.split(':', 1)[1].strip().rstrip('/')
                        print(f"[OK] Domain: {d}")
                        return d
        except: pass
        return DEFAULT_DOMAIN

    def authenticate(self):
        print(f"[-] Siteye bağlanılıyor: {self.domain}")
        try:
            r = self.session.get(self.domain, timeout=20)
            
            if r.status_code != 200:
                print(f"[FATAL] Siteye ulaşılamadı. Durum Kodu: {r.status_code}")
                return False

            html = r.text
            
            # Anahtarları Regex ile ara
            ckey_m = re.search(r'name=["\']cKey["\']\s+value=["\']([^"\']+)["\']', html)
            cval_m = re.search(r'name=["\']cValue["\']\s+value=["\']([^"\']+)["\']', html)

            if ckey_m and cval_m:
                self.cKey = ckey_m.group(1)
                self.cValue = cval_m.group(1)
                print(f"[OK] Tokenlar alındı.")
                # API istekleri için headerları güncelle
                self.session.headers.update({"Referer": self.domain, "Origin": self.domain})
                return True
            else:
                print("[FATAL] Tokenlar bulunamadı. Cloudflare hala aktif olabilir.")
                return False
                
        except Exception as e:
            print(f"[FATAL] Bağlantı hatası: {e}")
            return False

    def get_category_items(self, cat_id):
        url = f"{self.domain}/bg/getserielistbychannel"
        data = { "cKey": self.cKey, "cValue": self.cValue, "curPage": "1", "channelId": cat_id, "languageId": "2,3,4" }
        items = []
        try:
            r = self.session.post(url, data=data, timeout=15)
            if r.status_code == 200:
                html = r.json().get('data', {}).get('html', '')
                matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html, re.DOTALL)
                for href, title in matches:
                    items.append({"title": title.strip(), "url": self.domain + href})
        except: pass
        return items

    def resolve_video(self, url):
        try:
            r = self.session.get(url, timeout=10)
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            if match:
                data = json.loads(match.group(1).replace('&quot;', '"'))
                decrypted = self.crypto.decrypt(data['salt'], data['iv'], data['ciphertext'])
                if decrypted:
                    src_match = re.search(r'src="([^"]+)"', decrypted)
                    if src_match:
                        iframe_url = self.domain + src_match.group(1)
                        r_ifr = self.session.get(iframe_url, headers={"Referer": self.domain}, timeout=10)
                        vid_match = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', r_ifr.text)
                        if vid_match: return vid_match.group(1)
        except: pass
        return None

def worker(client, item, category):
    link = client.resolve_video(item['url'])
    if link:
        return (f'#EXTINF:-1 group-title="{category}",{item["title"]}\n'
                f'#EXTVLCOPT:http-user-agent={client.session.headers["User-Agent"]}\n'
                f'#EXTVLCOPT:http-referrer={client.domain}/\n'
                f'{link}\n')
    return None

def main():
    print("--- DiziPal Network Sync ---")
    client = DiziPalClient()
    if not client.domain: sys.exit(1)
    
    if not client.authenticate(): sys.exit(1)
        
    print("[-] Kategoriler taranıyor...")
    playlist = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for cat in CATEGORIES:
            items = client.get_category_content(cat['id'])
            print(f"    > {cat['name']}: {len(items)} içerik bulundu.")
            for item in items:
                futures.append(executor.submit(worker, client, item, cat['name']))
        
        print(f"[-] {len(futures)} link çözülüyor...")
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.append(res)

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist:
                f.write(entry)
        print(f"[BAŞARILI] {len(playlist)} içerik kaydedildi.")
    else:
        print("[UYARI] Liste boş.")

if __name__ == "__main__":
    main()
