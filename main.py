import requests
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys
import re
import urllib3

# SSL Uyarılarını Kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- YAPILANDIRMA ---
STATIC_AES_KEY = "ywevqtjrurkwtqgz"
USER_AGENT = "speedrestapi"
X_REQUESTED_WITH = "com.bp.box"
REFERER_URL = "https://speedrestapi.com/"

# Kaynaklar
PRIMARY_URL = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
FALLBACK_URL = "https://static.staticsave.com/conn/ct.js"

# Eğer otomatik bulma çalışmazsa denenecek acil durum adresleri
EMERGENCY_DOMAINS = [
    "http://inattv20.cf",
    "http://inattv38.xyz",
    "http://inattv50.cf"
]

OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 20

class InatCrypto:
    def __init__(self):
        self.block_size = AES.block_size

    def decrypt(self, encrypted_text, key_text):
        """Esnek şifre çözme: Hata olsa bile veriyi kurtarmaya çalışır."""
        try:
            if not encrypted_text or not key_text: return None
            
            key = key_text.encode('utf-8')
            iv = key # IV = Key
            
            # Base64 temizliği
            encrypted_text = encrypted_text.strip().replace('\n', '').replace('\r', '')
            pad = len(encrypted_text) % 4
            if pad:
                encrypted_text += '=' * (4 - pad)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decoded = base64.b64decode(encrypted_text)
            
            # Padding hatası olsa bile decrypt edilmiş ham veriyi al
            decrypted_raw = cipher.decrypt(decoded)
            
            # Padding'i manuel temizle (PKCS7) veya text decode et
            try:
                return unpad(decrypted_raw, self.block_size).decode('utf-8')
            except:
                # Padding bozuksa utf-8 decode edip "printable" karakterleri al
                return decrypted_raw.decode('utf-8', errors='ignore').strip()
                
        except Exception as e:
            return None

class InatDomainFinder:
    def __init__(self, session, crypto):
        self.session = session
        self.crypto = crypto

    def extract_url_via_regex(self, text):
        """Metin içindeki http/https linkini bulur."""
        if not text: return None
        # URL regex (basit)
        match = re.search(r'(https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})+(?::\d+)?)', text)
        if match:
            return match.group(1)
        return None

    def find(self):
        domain = None
        
        # 1. Yöntem: Client.pem
        print("[-] Kaynak 1 (Client.pem) taranıyor...")
        try:
            r = self.session.get(PRIMARY_URL, verify=False, timeout=10)
            if r.status_code == 200:
                content = r.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
                parts = content.split(':')
                if len(parts) >= 2:
                    # Katman 1
                    l1 = self.crypto.decrypt(parts[0], parts[1])
                    if l1:
                        l1_parts = l1.split(':')
                        if len(l1_parts) >= 2:
                            # Katman 2
                            final = self.crypto.decrypt(l1_parts[0], l1_parts[1])
                            # JSON parse deneme
                            try:
                                data = json.loads(final)
                                if "DC10" in data: domain = data["DC10"]
                            except:
                                # JSON değilse Regex ile URL ara
                                domain = self.extract_url_via_regex(final)
        except Exception as e:
            print(f"    Hata: {e}")

        if domain: return domain

        # 2. Yöntem: Fallback ct.js
        print("[-] Kaynak 2 (ct.js) taranıyor...")
        try:
            r = self.session.get(FALLBACK_URL, verify=False, timeout=10)
            if r.status_code == 200:
                content = r.text.strip()
                
                # A: Direkt metin içinde URL var mı?
                domain = self.extract_url_via_regex(content)
                
                # B: Şifreli olabilir, çözüp bakalım
                if not domain:
                    decrypted = self.crypto.decrypt(content, STATIC_AES_KEY)
                    if decrypted:
                        # JSON mu?
                        try:
                            data = json.loads(decrypted)
                            if "DC10" in data: domain = data["DC10"]
                        except:
                            pass
                        # Değilse Regex ile URL ara
                        if not domain:
                            domain = self.extract_url_via_regex(decrypted)

        except Exception as e:
            print(f"    Hata: {e}")

        return domain

class InatProcessor:
    def __init__(self):
        self.crypto = InatCrypto()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-Requested-With": X_REQUESTED_WITH,
            "Referer": REFERER_URL,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        })
        
        # Domain Bulma Süreci
        finder = InatDomainFinder(self.session, self.crypto)
        self.base_url = finder.find()

        # Eğer hala bulunamadıysa acil durum listesini dene
        if not self.base_url:
            print("[!] Dinamik domain bulunamadı, acil durum listesi deneniyor...")
            for url in EMERGENCY_DOMAINS:
                print(f"    Deneniyor: {url}")
                try:
                    # Test isteği atalım
                    test = self.make_request(url, "")
                    if test: 
                        self.base_url = url
                        print(f"[+] Çalışan acil durum domaini: {url}")
                        break
                except:
                    continue
        
        if self.base_url:
            self.base_url = self.base_url.rstrip('/')

    def make_request(self, domain, path):
        url = f"{domain}/{path.lstrip('/')}"
        payload = f"1={STATIC_AES_KEY}&0={STATIC_AES_KEY}"
        try:
            r = self.session.post(url, data=payload, verify=False, timeout=15)
            if r.status_code != 200: return None
            
            # Yanıt şifreli mi?
            if ":" in r.text:
                parts = r.text.split(':')
                l1 = self.crypto.decrypt(parts[0], STATIC_AES_KEY)
                if not l1: return None
                
                l1_parts = l1.split(':')
                if len(l1_parts) < 1: return None
                
                final = self.crypto.decrypt(l1_parts[0], STATIC_AES_KEY)
                return json.loads(final) if final else None
            else:
                return json.loads(r.text)
        except:
            return None

    def get_api_data(self, path=""):
        if not self.base_url: return None
        return self.make_request(self.base_url, path)

    def parse_content(self, item, category):
        try:
            name = item.get('chName', item.get('diziName', 'Bilinmeyen'))
            img = item.get('chImg', item.get('diziImg', ''))
            url = item.get('chUrl', item.get('diziUrl', ''))
            ctype = item.get('chType', item.get('diziType', ''))
            
            final_url = ""
            
            # Canlı Yayın / Direkt Link
            if ctype in ['live_url', 'web', 'link', 'tekli_regex_lb_sh_3']:
                final_url = url
            
            # Dizi / Film (Detay İsteği)
            elif ctype in ['dizi', 'film'] or (url and url.endswith('.php')):
                det = self.get_api_data(url)
                if det:
                    if isinstance(det, list) and det:
                        final_url = det[0].get('diziUrl', det[0].get('chUrl', ''))
                    elif isinstance(det, dict):
                        final_url = det.get('diziUrl', det.get('chUrl', ''))
            
            if final_url and final_url.startswith("http"):
                if any(x in final_url for x in ["yandex", "vk.com", "drive.google"]): return None
                
                m3u = f'#EXTINF:-1 tvg-logo="{img}" group-title="{category}",{name}\n'
                m3u += f'#EXTVLCOPT:http-user-agent={USER_AGENT}\n'
                m3u += f'#EXTVLCOPT:http-referrer={REFERER_URL}\n'
                m3u += f"{final_url}\n"
                return m3u
        except:
            pass
        return None

def main():
    print("--- SİSTEM BAŞLATILIYOR ---")
    bot = InatProcessor()
    
    if not bot.base_url:
        print("[FATAL] Hiçbir domain çalışmadı. İşlem iptal.")
        sys.exit(1)
        
    print(f"[SUCCESS] Hedef Domain: {bot.base_url}")
    
    cats = bot.get_api_data("")
    if not cats:
        print("[FATAL] Kategori listesi boş.")
        sys.exit(1)
        
    print(f"[-] {len(cats)} kategori bulundu. Tarama başlıyor...")
    
    playlist = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = []
        for c in cats:
            c_name = c.get('catName', 'Genel')
            c_url = c.get('catUrl', '')
            
            if not c_url or any(bad in c_name for bad in ["Hata", "Destek", "Telegram"]):
                continue
            
            print(f"   > Kategori İndiriliyor: {c_name}")
            items = bot.get_api_data(c_url)
            
            if items and isinstance(items, list):
                for i in items:
                    futures.append(ex.submit(bot.parse_content, i, c_name))
        
        print(f"[-] {len(futures)} içerik için detay taraması yapılıyor...")
        
        for i, f in enumerate(concurrent.futures.as_completed(futures)):
            res = f.result()
            if res: playlist.append(res)
            if i % 50 == 0: print(f"    İşlenen: {i}/{len(futures)}")

    if playlist:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for p in playlist:
                f.write(p)
        print(f"\n[BİTTİ] {len(playlist)} içerik {OUTPUT_FILE} dosyasına kaydedildi.")
    else:
        print("\n[UYARI] Liste boş kaldı.")

if __name__ == "__main__":
    main()
