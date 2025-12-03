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
import random

# --- AYARLAR ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 20  # Tarayıcı olmadığı için yüksek thread sayısı kullanılabilir

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
    """Android uygulamasındaki şifre çözme mantığı"""
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
        # chrome124: Cloudflare'i geçmek için en güncel parmak izi
        self.session = requests.Session(impersonate="chrome124")
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "max-age=0",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        })
        
        self.domain = self._get_domain()
        self.cKey = None
        self.cValue = None

    def _get_domain(self):
        print("[-] Domain güncelleniyor...")
        try:
            # GitHub'a normal requests ile de gidilebilir ama curl_cffi garanti olsun
            r = self.session.get(DOMAIN_LIST_URL, timeout=10)
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
        """
        Ana sayfaya girer, Cloudflare'i (varsa) geçer ve HTML içinden
        gizli tokenları (cKey, cValue) Regex ile çeker.
        """
        print(f"[-] Siteye bağlanılıyor: {self.domain}")
        try:
            # İlk istek
            r = self.session.get(self.domain, timeout=20)
            
            # Cloudflare kontrolü
            if r.status_code in [403, 503]:
                print("[-] Cloudflare algılandı, otomatik bypass deneniyor...")
                # curl_cffi genellikle bunu otomatik halleder ama bazen cookie set edilmesi gerekir
                time.sleep(2)
                r = self.session.get(self.domain, timeout=20) # İkinci deneme
            
            html = r.text
            
            # Regex ile Tokenları Bul
            # Örnek: <input type="hidden" name="cKey" value="xyz...">
            ckey_match = re.search(r'name=["\']cKey["\']\s+value=["\']([^"\']+)["\']', html)
            if not ckey_match:
                 ckey_match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']cKey["\']', html)
                 
            cvalue_match = re.search(r'name=["\']cValue["\']\s+value=["\']([^"\']+)["\']', html)
            if not cvalue_match:
                 cvalue_match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']cValue["\']', html)

            if ckey_match and cvalue_match:
                self.cKey = ckey_match.group(1)
                self.cValue = cvalue_match.group(1)
                print(f"[OK] Kimlik doğrulama başarılı. Token: {self.cKey[:5]}...")
                
                # API istekleri için headerları güncelle
                self.session.headers.update({
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": f"{self.domain}/",
                    "Origin": self.domain,
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                })
                return True
            else:
                print("[FATAL] Tokenlar HTML içinde bulunamadı.")
                # Debug için kısa HTML
                # print(html[:1000]) 
                return False
                
        except Exception as e:
            print(f"[FATAL] Bağlantı hatası: {e}")
            return False

    def fetch_category(self, cat_id):
        """API'den kategori içeriğini çeker"""
        url = f"{self.domain}/bg/getserielistbychannel"
        data = {
            "cKey": self.cKey,
            "cValue": self.cValue,
            "curPage": "1",
            "channelId": cat_id,
            "languageId": "2,3,4"
        }
        
        items = []
        try:
            r = self.session.post(url, data=data, timeout=15)
            if r.status_code == 200:
                try:
                    json_resp = r.json()
                    html_content = json_resp.get('data', {}).get('html', '')
                    
                    # HTML içindeki linkleri regex ile sök
                    # <a href="LINK"> ... <div class="...">TITLE</div>
                    matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html_content, re.DOTALL)
                    
                    for href, title in matches:
                        full_url = href if href.startswith("http") else f"{self.domain}{href}"
                        items.append({
                            "title": title.strip(),
                            "url": full_url
                        })
                except: pass
        except Exception as e:
            print(f"    Kategori hatası: {e}")
        return items

    def resolve_video(self, url):
        """Video sayfasındaki şifreyi çözer ve linki alır"""
        try:
            # Sayfaya git
            r = self.session.get(url, timeout=10)
            
            # Şifreli veriyi bul (data-rm-k)
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            
            if match:
                # HTML entity temizliği
                json_str = match.group(1).replace('&quot;', '"')
                data = json.loads(json_str)
                
                # Şifreyi çöz
                decrypted = self.crypto.decrypt(data['salt'], data['iv'], data['ciphertext'])
                
                if decrypted:
                    # İframe linkini bul
                    src_match = re.search(r'src="([^"]+)"', decrypted)
                    if src_match:
                        iframe_url = src_match.group(1)
                        if not iframe_url.startswith("http"): 
                            iframe_url = self.domain + iframe_url
                        
                        # İframe içine gir
                        r_ifr = self.session.get(iframe_url, headers={"Referer": self.domain}, timeout=10)
                        
                        # .m3u8 linkini bul
                        vid_match = re.search(r'file:\s*["\']([^"\']+\.m3u8[^"\']*)["\']', r_ifr.text)
                        if vid_match: return vid_match.group(1)
                        
                        # Alternatif .mp4
                        mp4_match = re.search(r'file:\s*["\']([^"\']+\.mp4[^"\']*)["\']', r_ifr.text)
                        if mp4_match: return mp4_match.group(1)
                        
                        # Genel kaynak
                        gen_match = re.search(r'source:\s*["\']([^"\']+)["\']', r_ifr.text)
                        if gen_match: return gen_match.group(1)
        except:
            pass
        return None

def worker(client, item, category):
    """Thread işçisi"""
    try:
        link = client.resolve_video(item['url'])
        if link and link.startswith("http"):
            # M3U Formatı
            return (
                f'#EXTINF:-1 group-title="{category}",{item["title"]}\n'
                f'#EXTVLCOPT:http-user-agent={client.session.headers["User-Agent"]}\n'
                f'#EXTVLCOPT:http-referrer={client.domain}/\n'
                f'{link}\n'
            )
    except:
        pass
    return None

def main():
    print("--- DiziPal Network Sync ---")
    
    client = DiziPalClient()
    
    # 1. Kimlik Doğrulama
    if not client.authenticate():
        print("[FATAL] Siteye erişim sağlanamadı. IP engelli veya yapı değişti.")
        sys.exit(1)
        
    # 2. İçerikleri Topla
    all_items = []
    print("[-] Kategoriler taranıyor...")
    
    # Kategori çekimlerini paralel yapalım
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_cat = {executor.submit(client.fetch_category, cat['id']): cat['name'] for cat in CATEGORIES}
        
        for future in concurrent.futures.as_completed(future_to_cat):
            cat_name = future_to_cat[future]
            items = future.result()
            print(f"    > {cat_name}: {len(items)} içerik")
            
            for item in items:
                all_items.append((item, cat_name))

    print(f"[INFO] Toplam {len(all_items)} içerik işlenecek. Linkler çözülüyor...")
    
    # 3. Linkleri Çöz (Yüksek Hız)
    playlist = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # İçerikleri karıştır ki aynı anda aynı URL'lere yüklenmeyelim
        random.shuffle(all_items)
        
        futures = [executor.submit(worker, client, item, cat_name) for item, cat_name in all_items]
        
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.append(res)
            
            completed += 1
            if completed % 50 == 0:
                print(f"    İlerleme: {completed}/{len(all_items)}")

    # 4. Kaydet
    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist:
                f.write(entry)
        print(f"\n[BAŞARILI] {len(playlist)} içerik kaydedildi -> {OUTPUT_FILE}")
    else:
        print("[HATA] Liste oluşturulamadı.")

if __name__ == "__main__":
    main()
