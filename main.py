from seleniumbase import SB
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
import xml.etree.ElementTree as ET

# --- AYARLAR ---
PASSPHRASE = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/Kraptor123/domainListesi/refs/heads/main/eklenti_domainleri.txt"
DEFAULT_DOMAIN = "https://dizipal1515.com"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 30 # Sitemap çok link içerdiği için worker sayısını artırdık

# Taklit Edilecek Tarayıcı İmzası
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

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

class DiziSiteManager:
    def __init__(self):
        self.domain = self._get_domain()
        self.cookies = {}
        self.crypto = CryptoUtils()
        # Hızlı istekler için curl_cffi oturumu
        self.session = requests.Session(impersonate="chrome120")

    def _get_domain(self):
        try:
            r = requests.get(DOMAIN_LIST_URL, timeout=5)
            if r.status_code == 200:
                parts = r.text.split('|')
                for part in parts:
                    if "DiziPalOrijinal" in part:
                        return part.split(':', 1)[1].strip().rstrip('/')
        except: pass
        return DEFAULT_DOMAIN

    def get_cookies_with_browser(self):
        """Sadece Cloudflare'i geçip Cookie almak için tarayıcı açar"""
        print("[-] Tarayıcı ile Cloudflare bypass ediliyor...")
        
        with SB(uc=True, headless=False) as sb:
            try:
                sb.open(self.domain)
                
                # Cloudflare kontrolü
                if "Just a moment" in sb.get_title():
                    print("[-] Cloudflare Challenge çözülüyor...")
                    sb.uc_gui_click_captcha()
                    time.sleep(6)
                
                # Sitenin yüklendiğinden emin ol (body tagini bekle)
                sb.wait_for_element("body", timeout=30)
                
                # Çerezleri al
                cookies = sb.get_cookies()
                for cookie in cookies:
                    self.cookies[cookie['name']] = cookie['value']
                
                # Session'a çerezleri yükle
                self.session.cookies.update(self.cookies)
                self.session.headers.update({
                    "User-Agent": sb.get_user_agent(),
                    "Referer": self.domain
                })
                
                print("[OK] Çerezler alındı. Hızlı moda geçiliyor.")
                return True
            except Exception as e:
                print(f"[FATAL] Tarayıcı hatası: {e}")
                return False

    def fetch_sitemap_links(self):
        """Sitemap.xml üzerinden tüm video linklerini toplar"""
        print("[-] Sitemap analiz ediliyor...")
        all_links = []
        
        # Ana sitemap'i dene
        sitemap_url = f"{self.domain}/sitemap.xml"
        try:
            r = self.session.get(sitemap_url, timeout=20)
            if r.status_code != 200:
                print("[!] Sitemap bulunamadı.")
                return []
            
            # XML Root
            root = ET.fromstring(r.content)
            
            # Sitemap Index mi yoksa URL listesi mi?
            # Genellikle sitemap_index.xml alt sitemapleri listeler
            sub_sitemaps = []
            
            # Namespace temizliği (bazen {http://...}loc gibi gelir)
            for child in root:
                url = ""
                for elem in child:
                    if "loc" in elem.tag:
                        url = elem.text
                        break
                
                if not url: continue

                # Alt sitemapleri bul
                if "sitemap" in url and url.endswith(".xml"):
                    sub_sitemaps.append(url)
                # Doğrudan linkleri bul (sadece dizi ve filmler)
                elif any(x in url for x in ["/dizi/", "/film/", "/bolum/"]):
                    all_links.append(url)
            
            # Alt sitemapleri tara
            for sub_url in sub_sitemaps:
                print(f"    > Alt harita taranıyor: {sub_url.split('/')[-1]}")
                try:
                    r_sub = self.session.get(sub_url, timeout=15)
                    sub_root = ET.fromstring(r_sub.content)
                    for child in sub_root:
                        for elem in child:
                            if "loc" in elem.tag:
                                url = elem.text
                                # Gereksiz sayfaları ele (etiketler, oyuncular vb.)
                                if any(x in url for x in ["/dizi/", "/film/"]) and not any(y in url for y in ["/oyuncu/", "/etiket/", "/kategori/"]):
                                    all_links.append(url)
                except:
                    continue

            # Benzersiz yap ve sırala
            all_links = list(set(all_links))
            print(f"[OK] Toplam {len(all_links)} içerik linki bulundu.")
            return all_links

        except Exception as e:
            print(f"[HATA] Sitemap okuma hatası: {e}")
            return []

    def extract_stream_from_html(self, url):
        """Verilen URL'ye gider ve videoyu çözer"""
        try:
            r = self.session.get(url, timeout=10)
            if r.status_code != 200: return None
            
            # Sayfa başlığını al (Kategori ve İsim için)
            soup = BeautifulSoup(r.content, 'lxml')
            page_title = soup.title.string.replace("İzle", "").replace("DiziPal", "").strip() if soup.title else "Bilinmeyen"
            
            # Şifreli veriyi bul
            match = re.search(r'data-rm-k=["\'](.*?)["\']', r.text)
            if match:
                json_str = match.group(1).replace('&quot;', '"')
                data = json.loads(json_str)
                
                decrypted = self.crypto.decrypt(data['salt'], data['iv'], data['ciphertext'])
                if decrypted:
                    # İframe src bul
                    src_match = re.search(r'src="([^"]+)"', decrypted)
                    if src_match:
                        iframe_url = src_match.group(1)
                        if not iframe_url.startswith("http"): iframe_url = self.domain + iframe_url
                        
                        # İframe içine gir
                        r_ifr = self.session.get(iframe_url, headers={"Referer": self.domain}, timeout=10)
                        
                        # Video dosyasını bul (.m3u8)
                        vid_match = re.search(r'file:\s*["\']([^"\']+\.m3u8[^"\']*)["\']', r_ifr.text)
                        if vid_match:
                            final_url = vid_match.group(1)
                            
                            # Kategori Tahmini (URL'den)
                            category = "Filmler" if "/film/" in url else "Diziler"
                            
                            return (
                                f'#EXTINF:-1 group-title="{category}",{page_title}\n'
                                f'#EXTVLCOPT:http-user-agent={self.session.headers["User-Agent"]}\n'
                                f'#EXTVLCOPT:http-referrer={self.domain}/\n'
                                f'{final_url}\n'
                            )
        except:
            pass
        return None

def main():
    print("--- DiziPal Sitemap Sync ---")
    manager = DiziSiteManager()
    
    # 1. Giriş Yap
    if not manager.get_cookies_with_browser():
        sys.exit(1)
        
    # 2. Linkleri Topla (Sitemap)
    links = manager.fetch_sitemap_links()
    
    if not links:
        print("[UYARI] Link bulunamadı.")
        sys.exit(1)
        
    # 3. Linkleri İşle (Multithreading)
    print(f"[-] {len(links)} içerik işleniyor (Max {MAX_WORKERS} thread)...")
    playlist = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Linkleri karıştır ki sunucuya yük dağılsın
        random.shuffle(links)
        
        futures = [executor.submit(manager.extract_stream_from_html, link) for link in links]
        
        completed = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                playlist.append(res)
            completed += 1
            if completed % 50 == 0:
                print(f"    İlerleme: {completed}/{len(links)}")

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist:
                f.write(entry)
        print(f"[BAŞARILI] {len(playlist)} içerik {OUTPUT_FILE} dosyasına yazıldı.")
    else:
        print("[HATA] Hiçbir video çözülemedi.")

if __name__ == "__main__":
    main()
