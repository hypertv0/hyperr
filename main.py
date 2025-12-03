from seleniumbase import SB
from bs4 import BeautifulSoup
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
import os

# --- AYARLAR (Smali Analizi) ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
# Eklentinin varsayılanı
DEFAULT_DOMAIN = "https://dizipal1515.com" 
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 8 # Cloudflare tekrar tetiklenmesin diye düşük tutuyoruz

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
    """Smali: DiziPalOrijinalKt.decrypt fonksiyonunun Python karşılığı"""
    def decrypt(self, salt_hex, iv_hex, ciphertext_b64):
        try:
            salt = bytes.fromhex(salt_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = base64.b64decode(ciphertext_b64)
            
            # PBKDF2WithHmacSHA512 (Java uyumlu)
            key = PBKDF2(PASSPHRASE, salt, dkLen=32, count=1000, hmac_hash_module=SHA512)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode('utf-8')
        except:
            return None

class DiziManager:
    def __init__(self):
        self.domain = self._get_domain()
        self.cookies = None
        self.user_agent = None
        self.cKey = None
        self.cValue = None
        self.crypto = CryptoUtils()

    def _get_domain(self):
        """GitHub'dan güncel adresi çeker"""
        try:
            r = requests.get(DOMAIN_LIST_URL, timeout=5)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        d = part.split(':', 1)[1].strip().rstrip('/')
                        print(f"[INFO] Güncel Domain: {d}")
                        return d
        except: pass
        return DEFAULT_DOMAIN

    def bypass_cloudflare_and_login(self):
        """
        SeleniumBase UC Modu ile siteye girer, Cloudflare'i geçer,
        tokenları (cKey, cValue) ve cookie'leri alır.
        """
        print("[-] Tarayıcı başlatılıyor (SeleniumBase UC)...")
        
        # SeleniumBase Context Manager (sb)
        # uc=True: Undetected Chrome modu (Anti-bot bypass)
        # headless=False: Xvfb kullanacağımız için GUI varmış gibi çalışır (Önemli!)
        with SB(uc=True, headless=False, page_load_strategy="eager") as sb:
            try:
                print(f"[-] Siteye gidiliyor: {self.domain}")
                sb.open(self.domain)
                
                # Cloudflare kontrolü ve bekleme
                if "Just a moment" in sb.get_title() or "Cloudflare" in sb.get_page_source():
                    print("[-] Cloudflare algılandı, bypass bekleniyor...")
                    # SeleniumBase otomatik olarak CF Turnstile'a tıklamayı dener
                    sb.uc_gui_click_captcha() 
                    time.sleep(5)
                
                # Site tamamen yüklensin diye bekle
                print("[-] Sayfa yükleniyor...")
                sb.wait_for_element('input[name="cKey"]', timeout=30)
                
                # Verileri Çek
                self.cKey = sb.get_attribute('input[name="cKey"]', "value")
                self.cValue = sb.get_attribute('input[name="cValue"]', "value")
                self.user_agent = sb.get_user_agent()
                
                # Cookie'leri al ve requests formatına çevir
                cookies_list = sb.get_cookies()
                self.cookies = {c['name']: c['value'] for c in cookies_list}
                
                print(f"[OK] Giriş Başarılı! Token: {self.cKey[:5]}...")
                return True
                
            except Exception as e:
                print(f"[FATAL] Tarayıcı hatası: {e}")
                # Hata anında ekran görüntüsü (Debug için)
                # sb.save_screenshot("error_page.png")
                return False

    def get_requests_session(self):
        """Tarayıcıdan alınan verilerle hızlı bir Requests oturumu oluşturur."""
        s = requests.Session()
        s.cookies.update(self.cookies)
        s.headers.update({
            "User-Agent": self.user_agent,
            "Referer": f"{self.domain}/",
            "Origin": self.domain,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "*/*"
        })
        return s

def worker_task(domain, session, crypto, cat_id, cat_name):
    """Her kategori için çalışacak işçi fonksiyon"""
    api_url = f"{domain}/bg/getserielistbychannel"
    
    # HTML'den alınan tokenlar burada kullanılır
    payload = {
        "cKey": session.cKey_val, # Aşağıda inject edeceğiz
        "cValue": session.cValue_val,
        "curPage": "1",
        "channelId": cat_id,
        "languageId": "2,3,4"
    }
    
    results = []
    try:
        r = session.post(api_url, data=payload, timeout=20)
        if r.status_code == 200:
            html_data = r.json().get('data', {}).get('html', '')
            
            # Regex ile hızlıca linkleri ve başlıkları topla
            # HTML: <a href="..." ... <div class="text-white...">Title</div>
            matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html_data, re.DOTALL)
            
            print(f"    > {cat_name}: {len(matches)} içerik bulundu.")
            
            for href, title in matches:
                full_url = href if href.startswith("http") else f"{domain}{href}"
                
                # Detay sayfasına git ve videoyu çöz
                try:
                    r_det = session.get(full_url, timeout=10)
                    # Şifreli veriyi bul (Smali: data-rm-k)
                    enc_match = re.search(r'data-rm-k=["\'](.*?)["\']', r_det.text)
                    
                    final_link = None
                    if enc_match:
                        json_str = enc_match.group(1).replace('&quot;', '"')
                        jdata = json.loads(json_str)
                        
                        decrypted = crypto.decrypt(jdata['salt'], jdata['iv'], jdata['ciphertext'])
                        if decrypted:
                            # İframe linki
                            iframe_m = re.search(r'src="([^"]+)"', decrypted)
                            if iframe_m:
                                ifr_url = iframe_m.group(1)
                                if not ifr_url.startswith("http"): ifr_url = domain + ifr_url
                                
                                # İframe içine gir
                                r_ifr = session.get(ifr_url, headers={"Referer": domain}, timeout=10)
                                
                                # m3u8 veya mp4 ara
                                vid_m = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', r_ifr.text)
                                if vid_m: final_link = vid_m.group(1)
                    
                    if final_link:
                        entry = (
                            f'#EXTINF:-1 group-title="{cat_name}",{title.strip()}\n'
                            f'#EXTVLCOPT:http-user-agent={session.headers["User-Agent"]}\n'
                            f'#EXTVLCOPT:http-referrer={domain}/\n'
                            f'{final_link}\n'
                        )
                        results.append(entry)
                except:
                    continue
    except Exception as e:
        print(f"[HATA] {cat_name} işlenirken hata: {e}")
        
    return results

def main():
    print("--- DiziPal SeleniumBase System ---")
    
    mgr = DiziManager()
    
    # 1. Adım: Tarayıcı ile Giriş (Cloudflare Bypass)
    if not mgr.bypass_cloudflare_and_login():
        sys.exit(1)
        
    # 2. Adım: Hızlı Tarama için Session Hazırla
    session = mgr.get_requests_session()
    # Worker fonksiyonuna tokenları taşımak için session objesine ekliyoruz
    session.cKey_val = mgr.cKey
    session.cValue = mgr.cValue
    
    crypto = mgr.crypto
    domain = mgr.domain
    
    print("[-] Hızlı tarama başlatılıyor...")
    playlist = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for cat in CATEGORIES:
            futures.append(executor.submit(worker_task, domain, session, crypto, cat['id'], cat['name']))
            
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.extend(res)
            completed += 1
            print(f"    Kategori Tamamlandı: {completed}/{len(CATEGORIES)}")

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist:
                f.write(entry)
        print(f"\n[BAŞARILI] {len(playlist)} içerik kaydedildi -> {OUTPUT_FILE}")
    else:
        print("\n[UYARI] Liste boş.")

if __name__ == "__main__":
    main()
