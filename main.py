from DrissionPage import ChromiumPage, ChromiumOptions
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

class DiziBrowser:
    def __init__(self):
        self.domain = self.find_domain()
        self.cookies = None
        self.user_agent = None
        self.cKey = None
        self.cValue = None
        self.crypto = CryptoUtils()

    def find_domain(self):
        print("[-] Domain aranıyor...")
        try:
            r = requests.get(DOMAIN_LIST_URL, timeout=5)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        dom = part.split(':', 1)[1].strip().rstrip('/')
                        print(f"[OK] Domain: {dom}")
                        return dom
        except: pass
        return DEFAULT_DOMAIN

    def bypass_cloudflare_and_get_tokens(self):
        print("[-] Tarayıcı başlatılıyor (Cloudflare Bypass)...")
        
        # Tarayıcı Ayarları (Linux Server için Optimize)
        co = ChromiumOptions()
        co.set_argument('--headless=new') # Arayüzsüz mod (GitHub Actions için şart)
        co.set_argument('--no-sandbox')
        co.set_argument('--disable-gpu')
        
        # Android Uygulaması gibi görünelim
        app_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0"
        co.set_user_agent(app_ua)

        page = ChromiumPage(co)
        
        try:
            print(f"[-] Siteye gidiliyor: {self.domain}")
            page.get(self.domain)
            
            # Cloudflare kontrolü - 20 saniye bekle
            # cKey inputu sayfada var mı diye bakar. Varsa CF geçilmiş demektir.
            print("[-] Cloudflare kontrolü bekleniyor...")
            
            # Sayfanın tam yüklenmesini ve cKey elementinin oluşmasını bekle
            # Bu element sadece site tamamen açıldığında HTML'de olur.
            ele = page.ele('css:input[name="cKey"]', timeout=30)
            
            if ele:
                print("[OK] Site başarıyla açıldı!")
                # Tokenları al
                self.cKey = page.ele('css:input[name="cKey"]').attr('value')
                self.cValue = page.ele('css:input[name="cValue"]').attr('value')
                
                # Cookie ve UA al (Sonraki requests istekleri için)
                self.cookies = page.cookies.as_dict()
                self.user_agent = page.user_agent
                
                print(f"[OK] Token: {self.cKey[:5]}... | Cookies alındı.")
                return True
            else:
                print("[FATAL] 30 saniye beklendi ama site açılmadı (Cloudflare veya HTML değişti).")
                # Debug için sayfa başlığını yaz
                print(f"Sayfa Başlığı: {page.title}")
                return False

        except Exception as e:
            print(f"[HATA] Tarayıcı hatası: {e}")
            return False
        finally:
            page.quit()

    def get_api_session(self):
        """Requests için oturum oluşturur (Tarayıcıdan alınan verilerle)"""
        s = requests.Session()
        s.cookies.update(self.cookies)
        s.headers.update({
            "User-Agent": self.user_agent,
            "Referer": f"{self.domain}/",
            "Origin": self.domain,
            "X-Requested-With": "XMLHttpRequest"
        })
        return s

    def get_video_link(self, session, url):
        """Video sayfasındaki şifreli veriyi çözer"""
        try:
            r = session.get(url, timeout=10)
            
            # Regex ile şifreli veriyi bul
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            if match:
                data = json.loads(match.group(1).replace('&quot;', '"'))
                decrypted = self.crypto.decrypt(data['salt'], data['iv'], data['ciphertext'])
                
                if decrypted:
                    # İframe linki
                    iframe_match = re.search(r'src="([^"]+)"', decrypted)
                    if iframe_match:
                        iframe_url = iframe_match.group(1)
                        if not iframe_url.startswith("http"): iframe_url = self.domain + iframe_url
                        
                        # İframe sayfasına git
                        r2 = session.get(iframe_url, headers={"Referer": self.domain}, timeout=10)
                        
                        # .m3u8 bul
                        m3u = re.search(r'file:\s*["\']([^"\']+\.m3u8[^"\']*)["\']', r2.text)
                        if m3u: return m3u.group(1)
                        
                        # .mp4 bul
                        mp4 = re.search(r'file:\s*["\']([^"\']+\.mp4[^"\']*)["\']', r2.text)
                        if mp4: return mp4.group(1)
        except:
            pass
        return None

def worker_task(scraper_data, cat_id, cat_name):
    domain, cKey, cValue, cookies, ua = scraper_data
    
    # Worker içinde yeni session (Thread-safe olması için)
    s = requests.Session()
    s.cookies.update(cookies)
    s.headers.update({
        "User-Agent": ua,
        "Referer": f"{domain}/",
        "Origin": domain,
        "X-Requested-With": "XMLHttpRequest"
    })
    
    api_url = f"{domain}/bg/getserielistbychannel"
    payload = {
        "cKey": cKey,
        "cValue": cValue,
        "curPage": "1",
        "channelId": cat_id,
        "languageId": "2,3,4"
    }
    
    entries = []
    try:
        # Kategoriyi çek
        r = s.post(api_url, data=payload, timeout=20)
        if r.status_code == 200:
            html = r.json().get('data', {}).get('html', '')
            # Linkleri bul
            matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html, re.DOTALL)
            
            print(f"    > {cat_name}: {len(matches)} içerik taramaya alındı.")
            
            # İçerikleri işle
            crypto = CryptoUtils()
            for href, title in matches:
                full_url = href if href.startswith("http") else f"{domain}{href}"
                
                # Video linkini çöz (Aynı lojik worker içinde)
                try:
                    # Detay isteği
                    rd = s.get(full_url, timeout=10)
                    rm_match = re.search(r'data-rm-k=["\'](.*?)["\']', rd.text)
                    
                    final_link = None
                    if rm_match:
                        jdata = json.loads(rm_match.group(1).replace('&quot;', '"'))
                        dec = crypto.decrypt(jdata['salt'], jdata['iv'], jdata['ciphertext'])
                        if dec:
                            ifr = re.search(r'src="([^"]+)"', dec)
                            if ifr:
                                iurl = ifr.group(1)
                                if not iurl.startswith("http"): iurl = domain + iurl
                                
                                r_ifr = s.get(iurl, headers={"Referer": domain}, timeout=10)
                                vid = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', r_ifr.text)
                                if vid: final_link = vid.group(1)
                    
                    if final_link:
                        m3u = f'#EXTINF:-1 group-title="{cat_name}",{title.strip()}\n'
                        m3u += f'#EXTVLCOPT:http-user-agent={ua}\n'
                        m3u += f'#EXTVLCOPT:http-referrer={domain}/\n'
                        m3u += f'{final_link}\n'
                        entries.append(m3u)
                except:
                    continue
    except Exception as e:
        print(f"[HATA] Kategori hatası ({cat_name}): {e}")
        
    return entries

def main():
    print("--- DiziPal Sync V6 (Browser Engine) ---")
    
    browser = DiziBrowser()
    
    # 1. Aşama: Browser ile giriş yapıp çerezleri çal
    if not browser.bypass_cloudflare_and_get_tokens():
        sys.exit(1)
        
    # Verileri paketle (Workerlara göndermek için)
    scraper_data = (browser.domain, browser.cKey, browser.cValue, browser.cookies, browser.user_agent)
    
    all_entries = []
    
    # 2. Aşama: Hızlı tarama (Requests ile)
    # Tarayıcıyı kapattık, artık requests kullanabiliriz çünkü elimizde geçerli cookie var.
    print("[-] İçerik taraması başlıyor (Requests modu)...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for cat in CATEGORIES:
            futures.append(executor.submit(worker_task, scraper_data, cat['id'], cat['name']))
            
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                all_entries.extend(res)

    # Kaydet
    if all_entries:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in all_entries:
                f.write(entry)
        print(f"[BAŞARILI] Toplam {len(all_entries)} içerik kaydedildi.")
    else:
        print("[UYARI] Liste boş kaldı.")

if __name__ == "__main__":
    main()
