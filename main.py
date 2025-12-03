import requests
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys
import urllib3
import random

# SSL Sertifika Hatalarını Görmezden Gel
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SABİT AYARLAR ---
STATIC_AES_KEY = "ywevqtjrurkwtqgz"
# User-Agent: Samsung Galaxy S10 taklidi yaparak engellemeyi aşmayı dener
USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 10; SM-G973F Build/QP1A.190711.020)"
X_REQUESTED_WITH = "com.bp.box"
REFERER_URL = "https://speedrestapi.com/"

# Bu adresler GitHub IP'lerinden genellikle engellidir ama yine de dursun
PRIMARY_CERT = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
FALLBACK_CT = "https://static.staticsave.com/conn/ct.js"

OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 30  # Tarama hızı için yüksek thread sayısı

class InatCrypto:
    def __init__(self):
        self.block_size = AES.block_size

    def decrypt(self, encrypted_text, key_text):
        """AES-128-CBC Şifre Çözme (IV = Key)"""
        try:
            if not encrypted_text or not key_text: return None
            key = key_text.encode('utf-8')
            # Uygulamada IV, Key ile aynı byte dizisidir
            iv = key 
            
            # Base64 fix
            encrypted_text = encrypted_text.strip().replace('\n', '').replace('\r', '')
            pad = len(encrypted_text) % 4
            if pad: encrypted_text += '=' * (4 - pad)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decoded = base64.b64decode(encrypted_text)
            decrypted_raw = cipher.decrypt(decoded)
            
            # Padding temizleme (Hata toleranslı)
            try:
                return unpad(decrypted_raw, self.block_size).decode('utf-8')
            except:
                return decrypted_raw.decode('utf-8', errors='ignore').strip()
        except:
            return None

class InatScanner:
    def __init__(self, session, crypto):
        self.session = session
        self.crypto = crypto

    def check_url(self, domain):
        """Bir domainin aktif Inat sunucusu olup olmadığını dener."""
        try:
            # URL sonundaki slash'i temizle
            base = domain.rstrip('/')
            # API'ye boş bir POST isteği at (Ana sayfa verisi için)
            url = f"{base}/"
            
            # API, şifreli bir body bekler: 1=KEY&0=KEY
            payload = f"1={STATIC_AES_KEY}&0={STATIC_AES_KEY}"
            
            # Timeout'u kısa tutuyoruz ki hızlı tarasın (3 saniye)
            r = self.session.post(url, data=payload, timeout=3, verify=False)
            
            # 200 OK dönerse ve içerik şifreli formatta ise (Data:Key) bu doğru sunucudur
            if r.status_code == 200:
                if ":" in r.text or "chName" in r.text or "diziName" in r.text:
                    return base
        except:
            pass
        return None

    def scan_brute_force(self):
        """Olası domainleri (inattv100.xyz ... inattv180.xyz) tarar."""
        print("[-] Statik kaynaklara erişilemedi. Aktif sunucu taranıyor...")
        
        potential_urls = []
        
        # 1. Olasılık: .xyz uzantılı domainler (En yaygın)
        # Güncel aralık genellikle 120-170 arasıdır.
        for i in range(110, 180):
            potential_urls.append(f"https://inattv{i}.xyz")
            potential_urls.append(f"http://inattv{i}.xyz")
            
        # 2. Olasılık: .link ve .com uzantıları
        for i in range(110, 180):
            potential_urls.append(f"https://inattv{i}.link")
            potential_urls.append(f"https://inattv{i}.com")

        found_domain = None
        
        # Çoklu iş parçacığı ile tarama
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_url = {executor.submit(self.check_url, url): url for url in potential_urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                result = future.result()
                if result:
                    found_domain = result
                    print(f"[!!!] GÜNCEL SUNUCU BULUNDU: {found_domain}")
                    # Bulduğumuz anda diğerlerini iptal etmeye çalışalım
                    executor.shutdown(wait=False)
                    break
        
        return found_domain

    def find_domain(self):
        # Önce klasik yöntemleri dene (Github IP'si bloklu değilse çalışır)
        try:
            r = self.session.get(PRIMARY_CERT, verify=False, timeout=5)
            if r.status_code == 200:
                content = r.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
                parts = content.split(':')
                if len(parts) >= 2:
                    l1 = self.crypto.decrypt(parts[0], parts[1])
                    if l1:
                        l1p = l1.split(':')
                        fin = self.crypto.decrypt(l1p[0], l1p[1])
                        d = json.loads(fin)
                        if "DC10" in d: return d["DC10"]
        except: pass

        # Fallback
        try:
            r = self.session.get(FALLBACK_CT, verify=False, timeout=5)
            if r.status_code == 200:
                txt = r.text.strip()
                if txt.startswith("http"): return txt
                dec = self.crypto.decrypt(txt, STATIC_AES_KEY)
                if dec and "http" in dec: return dec
        except: pass

        # Hiçbiri çalışmadıysa TARAMA MODUNA geç
        return self.scan_brute_force()

class InatProcessor:
    def __init__(self):
        self.crypto = InatCrypto()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-Requested-With": X_REQUESTED_WITH,
            "Referer": REFERER_URL,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "*/*"
        })
        
        scanner = InatScanner(self.session, self.crypto)
        self.base_url = scanner.find_domain()
        
        if self.base_url:
            self.base_url = self.base_url.rstrip('/')

    def api_request(self, path=""):
        if not self.base_url: return None
        url = f"{self.base_url}/{path.lstrip('/')}"
        payload = f"1={STATIC_AES_KEY}&0={STATIC_AES_KEY}"
        
        try:
            r = self.session.post(url, data=payload, verify=False, timeout=20)
            if r.status_code != 200: return None
            
            text = r.text
            # Şifreli yanıt
            if ":" in text:
                parts = text.split(':')
                l1 = self.crypto.decrypt(parts[0], STATIC_AES_KEY)
                if not l1: return None
                l1p = l1.split(':')
                fin = self.crypto.decrypt(l1p[0], STATIC_AES_KEY)
                if fin: return json.loads(fin)
            # Şifresiz yanıt
            elif "{" in text:
                return json.loads(text)
        except:
            pass
        return None

    def parse_channel(self, item, cat_name):
        try:
            name = item.get('chName', item.get('diziName', 'Bilinmeyen'))
            img = item.get('chImg', item.get('diziImg', ''))
            url = item.get('chUrl', item.get('diziUrl', ''))
            ctype = item.get('chType', item.get('diziType', ''))
            
            final_url = ""
            
            # Canlı Yayın / Web Linki
            if ctype in ['live_url', 'web', 'link', 'tekli_regex_lb_sh_3']:
                final_url = url
                
            # Dizi / Film (Detay İsteği)
            elif ctype in ['dizi', 'film'] or (url and url.endswith('.php')):
                # Derin tarama: Video detaylarını çek
                try:
                    det = self.api_request(url)
                    if det:
                        # Dönen veri liste veya obje olabilir
                        if isinstance(det, list) and len(det) > 0:
                            final_url = det[0].get('diziUrl', det[0].get('chUrl', ''))
                        elif isinstance(det, dict):
                            final_url = det.get('diziUrl', det.get('chUrl', ''))
                except: pass

            # URL Kontrolü
            if final_url and final_url.startswith("http"):
                # Çalışmayan kaynakları ele
                if any(x in final_url for x in ["yandex", "vk.com", "drive.google", "cloud.mail.ru"]):
                    return None
                
                # Boşlukları düzelt
                final_url = final_url.replace(" ", "%20")
                
                # M3U Entry Oluştur
                entry = f'#EXTINF:-1 tvg-logo="{img}" group-title="{cat_name}",{name}\n'
                entry += f'#EXTVLCOPT:http-user-agent={USER_AGENT}\n'
                entry += f'#EXTVLCOPT:http-referrer={REFERER_URL}\n'
                entry += f"{final_url}\n"
                return entry

        except:
            pass
        return None

def main():
    print("--- BAŞLATILIYOR ---")
    bot = InatProcessor()
    
    if not bot.base_url:
        print("[FATAL] Hiçbir sunucuya erişilemedi (IP Ban veya Sunucu Kapalı).")
        sys.exit(1)
    
    print(f"[OK] Hedef: {bot.base_url}")
    print("[-] Kategoriler alınıyor...")
    
    cats = bot.api_request("")
    
    if not cats:
        print("[FATAL] Kategori listesi alınamadı.")
        sys.exit(1)
        
    print(f"[-] {len(cats)} kategori bulundu. İçerik taranıyor...")
    
    playlist = []
    
    # Paralel İşleme
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for c in cats:
            c_name = c.get('catName', 'Genel')
            c_url = c.get('catUrl', '')
            
            # Gereksiz kategorileri atla
            if not c_url or any(x in c_name for x in ["Hata", "Destek", "Telegram", "Duyuru"]):
                continue
                
            print(f"   > {c_name}")
            items = bot.api_request(c_url)
            
            if items and isinstance(items, list):
                for item in items:
                    futures.append(executor.submit(bot.parse_channel, item, c_name))
        
        # Sonuçları Topla
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist.append(res)

    # Yaz
    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for p in playlist:
                f.write(p)
        print(f"\n[BAŞARILI] {len(playlist)} kanal/film eklendi -> {OUTPUT_FILE}")
    else:
        print("\n[UYARI] Liste boş kaldı.")

if __name__ == "__main__":
    main()
