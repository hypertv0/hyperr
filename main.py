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

# --- AYARLAR ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com" 
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 10

# Uygulamanın kullandığı User-Agent (Smali'den alındı)
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

class DiziManager:
    def __init__(self):
        self.domain = self._get_domain()
        self.cookies = None
        self.user_agent = None
        self.cKey = None
        self.cValue = None
        self.crypto = CryptoUtils()

    def _get_domain(self):
        try:
            r = requests.get(DOMAIN_LIST_URL, timeout=5)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        d = part.split(':', 1)[1].strip().rstrip('/')
                        print(f"[INFO] Domain: {d}")
                        return d
        except: pass
        return DEFAULT_DOMAIN

    def bypass_cloudflare_and_login(self):
        """
        SeleniumBase UC Modu ile siteye girer, kaynak kodunu regex ile tarar.
        """
        print("[-] Tarayıcı başlatılıyor (SeleniumBase UC)...")
        
        # headless=False: Xvfb olduğu için GUI modunda açıyoruz (CF için daha iyi)
        with SB(uc=True, headless=False, agent=APP_USER_AGENT) as sb:
            try:
                print(f"[-] Siteye gidiliyor: {self.domain}")
                
                # Cloudflare'i zorla geçmek için reconnect kullanıyoruz
                sb.uc_open_with_reconnect(self.domain, reconnect_time=6)
                
                # Captcha varsa tıkla
                try: sb.uc_gui_click_captcha()
                except: pass
                
                print("[-] Sayfa yüklenmesi bekleniyor...")
                time.sleep(5) # JavaScriptlerin çalışması için bekle
                
                # Sayfayı biraz kaydır (Lazy load veya tetikleyiciler için)
                sb.scroll_to_bottom()
                time.sleep(2)
                
                # Kaynak kodunu al
                page_source = sb.get_page_source()
                
                # Regex ile cKey ve cValue ara (HTML elementini beklemek yerine text içinde arıyoruz)
                # input name="cKey" value="XYZ"
                print("[-] Tokenlar Regex ile aranıyor...")
                
                ckey_match = re.search(r'name=["\']cKey["\']\s+value=["\']([^"\']+)["\']', page_source)
                cvalue_match = re.search(r'name=["\']cValue["\']\s+value=["\']([^"\']+)["\']', page_source)
                
                if ckey_match and cvalue_match:
                    self.cKey = ckey_match.group(1)
                    self.cValue = cvalue_match.group(1)
                else:
                    # Belki sıralama farklıdır: value="XYZ" name="cKey"
                    ckey_match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']cKey["\']', page_source)
                    cvalue_match = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']cValue["\']', page_source)
                    
                    if ckey_match and cvalue_match:
                        self.cKey = ckey_match.group(1)
                        self.cValue = cvalue_match.group(1)
                
                if self.cKey and self.cValue:
                    # Cookie ve UA al
                    self.user_agent = sb.get_user_agent()
                    cookies_list = sb.get_cookies()
                    self.cookies = {c['name']: c['value'] for c in cookies_list}
                    
                    print(f"[OK] Token Bulundu: {self.cKey[:5]}...")
                    return True
                else:
                    print("[FATAL] Tokenlar kaynak kodunda bulunamadı.")
                    # Debug: Sayfa başlığını ve kaynağın bir kısmını yazdır
                    print(f"Title: {sb.get_title()}")
                    print(f"HTML Sample: {page_source[:500]}")
                    return False
                
            except Exception as e:
                print(f"[FATAL] Tarayıcı hatası: {e}")
                return False

    def get_requests_session(self):
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
    api_url = f"{domain}/bg/getserielistbychannel"
    
    payload = {
        "cKey": session.cKey_val,
        "cValue": session.cValue_val,
        "curPage": "1",
        "channelId": cat_id,
        "languageId": "2,3,4"
    }
    
    results = []
    try:
        r = session.post(api_url, data=payload, timeout=20)
        if r.status_code == 200:
            try:
                html_data = r.json().get('data', {}).get('html', '')
            except:
                # JSON dönmezse HTML dönmüş olabilir mi?
                html_data = r.text

            matches = re.findall(r'href="([^"]+)".*?text-white text-sm">([^<]+)', html_data, re.DOTALL)
            
            print(f"    > {cat_name}: {len(matches)} içerik bulundu.")
            
            for href, title in matches:
                full_url = href if href.startswith("http") else f"{domain}{href}"
                
                try:
                    r_det = session.get(full_url, timeout=10)
                    enc_match = re.search(r'data-rm-k=["\'](.*?)["\']', r_det.text)
                    
                    final_link = None
                    if enc_match:
                        json_str = enc_match.group(1).replace('&quot;', '"')
                        try:
                            jdata = json.loads(json_str)
                            decrypted = crypto.decrypt(jdata['salt'], jdata['iv'], jdata['ciphertext'])
                            if decrypted:
                                ifr_m = re.search(r'src="([^"]+)"', decrypted)
                                if ifr_m:
                                    ifr_url = ifr_m.group(1)
                                    if not ifr_url.startswith("http"): ifr_url = domain + ifr_url
                                    
                                    r_ifr = session.get(ifr_url, headers={"Referer": domain}, timeout=10)
                                    
                                    # m3u8 veya mp4 ara
                                    vid_m = re.search(r'file:\s*["\']([^"\']+\.(?:m3u8|mp4)[^"\']*)["\']', r_ifr.text)
                                    if vid_m: final_link = vid_m.group(1)
                                    else:
                                        # source: '...'
                                        src_m = re.search(r'source:\s*["\']([^"\']+)["\']', r_ifr.text)
                                        if src_m: final_link = src_m.group(1)
                        except: pass
                    
                    if final_link:
                        # Türkçe karakterleri düzelt
                        clean_title = title.strip()
                        m3u = (
                            f'#EXTINF:-1 group-title="{cat_name}",{clean_title}\n'
                            f'#EXTVLCOPT:http-user-agent={session.headers["User-Agent"]}\n'
                            f'#EXTVLCOPT:http-referrer={domain}/\n'
                            f'{final_link}\n'
                        )
                        results.append(m3u)
                except:
                    continue
    except Exception as e:
        pass
        
    return results

def main():
    print("--- DiziPal SeleniumBase V7 ---")
    
    mgr = DiziManager()
    
    if not mgr.bypass_cloudflare_and_login():
        sys.exit(1)
        
    session = mgr.get_requests_session()
    # Worker'lara taşımak için
    session.cKey_val = mgr.cKey
    session.cValue = mgr.cValue
    
    crypto = mgr.crypto
    domain = mgr.domain
    
    print("[-] Tarama başlıyor...")
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
            print(f"    Kategori İlerlemesi: {completed}/{len(CATEGORIES)}")

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist:
                f.write(entry)
        print(f"\n[BAŞARILI] {len(playlist)} içerik kaydedildi.")
    else:
        print("\n[UYARI] Liste boş kaldı.")

if __name__ == "__main__":
    main()
