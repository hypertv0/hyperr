import requests
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys
import urllib3

# SSL Uyarılarını Kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- SABİT AYARLAR (Smali Analizinden) ---
STATIC_AES_KEY = "ywevqtjrurkwtqgz"
USER_AGENT = "speedrestapi"
X_REQUESTED_WITH = "com.bp.box"
REFERER_URL = "https://speedrestapi.com/"

# Kaynak URL'ler
PRIMARY_URL = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
FALLBACK_URL = "https://static.staticsave.com/conn/ct.js"

OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 25

class InatCrypto:
    def __init__(self):
        self.block_size = AES.block_size

    def safe_base64_decode(self, data):
        """Java Base64.decode toleransını simüle eder."""
        if not data: return None
        # Gereksiz karakterleri temizle
        data = data.replace('\n', '').replace('\r', '').strip()
        # Padding ekle
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        try:
            return base64.b64decode(data)
        except:
            return None

    def decrypt(self, encrypted_text, key_text):
        """
        Smali: InatBoxModelsKt.decryptAES
        AES-128-CBC, Key = IV
        """
        try:
            if not encrypted_text or not key_text: return None
            
            key_bytes = key_text.encode('utf-8')
            iv_bytes = key_bytes # Smali kodunda IV, Key ile aynıdır
            
            encrypted_bytes = self.safe_base64_decode(encrypted_text)
            if not encrypted_bytes: return None

            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), self.block_size)
            
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return None

class InatResolver:
    def __init__(self, crypto, session):
        self.crypto = crypto
        self.session = session

    def get_domain(self):
        # Adım 1: Client.pem (Çift Katmanlı Şifreleme)
        print("[-] Yöntem 1 (Client.pem) deneniyor...")
        try:
            r = self.session.get(PRIMARY_URL, verify=False, timeout=15)
            if r.status_code == 200:
                raw = r.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
                parts = raw.split(':')
                if len(parts) >= 2:
                    # Katman 1
                    cipher_text = parts[0]
                    dynamic_key = parts[1]
                    layer1 = self.crypto.decrypt(cipher_text, dynamic_key)
                    
                    if layer1:
                        l1_parts = layer1.split(':')
                        if len(l1_parts) >= 2:
                            # Katman 2
                            final_json = self.crypto.decrypt(l1_parts[0], l1_parts[1])
                            if final_json:
                                try:
                                    data = json.loads(final_json)
                                    if "DC10" in data:
                                        print(f"[+] Domain Bulundu (Client.pem): {data['DC10']}")
                                        return data['DC10']
                                except: pass
        except Exception as e:
            print(f"[!] Yöntem 1 hatası: {e}")

        # Adım 2: Fallback (ct.js)
        print("[-] Yöntem 2 (Fallback ct.js) deneniyor...")
        try:
            r = self.session.get(FALLBACK_URL, verify=False, timeout=15)
            if r.status_code == 200:
                content = r.text.strip()
                
                # Durum A: Direkt URL
                if content.startswith("http"):
                    print(f"[+] Domain Bulundu (Plain Text): {content}")
                    return content

                # Durum B: JSON {"DC10": "..."}
                try:
                    data = json.loads(content)
                    if "DC10" in data:
                        print(f"[+] Domain Bulundu (JSON): {data['DC10']}")
                        return data['DC10']
                except: pass

                # Durum C: Şifreli Metin (Statik Key ile)
                decrypted = self.crypto.decrypt(content, STATIC_AES_KEY)
                if decrypted:
                    if decrypted.startswith("http"):
                        print(f"[+] Domain Bulundu (Decrypted Text): {decrypted}")
                        return decrypted
                    try:
                        data = json.loads(decrypted)
                        if "DC10" in data:
                            print(f"[+] Domain Bulundu (Decrypted JSON): {data['DC10']}")
                            return data['DC10']
                    except: pass

        except Exception as e:
            print(f"[!] Yöntem 2 hatası: {e}")

        return None

class InatScraper:
    def __init__(self):
        self.crypto = InatCrypto()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-Requested-With": X_REQUESTED_WITH,
            "Referer": REFERER_URL,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        })
        
        resolver = InatResolver(self.crypto, self.session)
        self.domain = resolver.get_domain()
        
        if self.domain:
            self.domain = self.domain.rstrip('/')

    def request_api(self, path=""):
        if not self.domain: return None
        
        url = f"{self.domain}/{path.lstrip('/')}"
        # API static dosya ise (örn: .php değilse) GET, yoksa POST
        # Ancak Inat genelde POST ve şifreli body ister
        payload = f"1={STATIC_AES_KEY}&0={STATIC_AES_KEY}"
        
        try:
            # Smali: makeInatRequest her zaman POST atar
            resp = self.session.post(url, data=payload, verify=False, timeout=20)
            
            if resp.status_code != 200: return None
            
            text = resp.text
            if not text: return None

            # Yanıt şifreli mi? (İki nokta üst üste içerir: Data:Key)
            if ":" in text:
                parts = text.split(':')
                # Katman 1
                layer1 = self.crypto.decrypt(parts[0], STATIC_AES_KEY)
                if not layer1: return None
                
                # Katman 2
                l1_parts = layer1.split(':')
                if len(l1_parts) < 1: return None
                
                final_json = self.crypto.decrypt(l1_parts[0], STATIC_AES_KEY)
                return json.loads(final_json) if final_json else None
            else:
                # Şifresiz JSON dönmüş olabilir (Nadir)
                return json.loads(text)
                
        except Exception:
            return None

    def process_content(self, item, category):
        try:
            name = item.get('chName', item.get('diziName', 'Bilinmeyen'))
            img = item.get('chImg', item.get('diziImg', ''))
            url = item.get('chUrl', item.get('diziUrl', ''))
            ctype = item.get('chType', item.get('diziType', ''))
            
            final_url = ""
            
            # 1. Tip: Doğrudan Linkler
            if ctype in ['live_url', 'web', 'link', 'tekli_regex_lb_sh_3']:
                final_url = url
            
            # 2. Tip: Detay Gerektirenler
            elif ctype in ['dizi', 'film'] or (url and url.endswith('.php')):
                detail_data = self.request_api(url)
                if detail_data:
                    if isinstance(detail_data, list) and len(detail_data) > 0:
                        final_url = detail_data[0].get('diziUrl', detail_data[0].get('chUrl', ''))
                    elif isinstance(detail_data, dict):
                        final_url = detail_data.get('diziUrl', detail_data.get('chUrl', ''))
            
            # Link Kontrolü ve Temizliği
            if final_url and final_url.startswith("http"):
                if any(x in final_url for x in ["yandex", "vk.com", "drive.google"]):
                    return None # Desteklenmeyen kaynak
                
                m3u = f'#EXTINF:-1 tvg-logo="{img}" group-title="{category}",{name}\n'
                m3u += f'#EXTVLCOPT:http-user-agent={USER_AGENT}\n'
                m3u += f'#EXTVLCOPT:http-referrer={REFERER_URL}\n'
                m3u += f"{final_url}\n"
                return m3u

        except:
            pass
        return None

def main():
    scraper = InatScraper()
    if not scraper.domain:
        print("[!!!] Domain bulunamadı. Çıkılıyor.")
        sys.exit(1)
        
    print("[-] Kategoriler indiriliyor...")
    categories = scraper.request_api("")
    
    if not categories:
        print("[!!!] Kategori listesi boş veya şifre çözülemedi.")
        sys.exit(1)

    print(f"[-] {len(categories)} kategori bulundu.")
    
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for cat in categories:
            c_name = cat.get('catName', 'Genel')
            c_url = cat.get('catUrl', '')
            
            if not c_url or any(x in c_name for x in ["Hata", "Destek", "Telegram"]):
                continue
            
            # Kategori içeriğini al
            print(f"   > Taranıyor: {c_name}")
            channels = scraper.request_api(c_url)
            
            if channels and isinstance(channels, list):
                for ch in channels:
                    futures.append(executor.submit(scraper.process_content, ch, c_name))
        
        print(f"[-] {len(futures)} içerik işleniyor...")
        
        count = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                results.append(res)
            count += 1
            if count % 100 == 0:
                print(f"    İlerleme: {count}/{len(futures)}")

    if results:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for line in results:
                f.write(line)
        print(f"[BAŞARILI] {len(results)} içerik {OUTPUT_FILE} dosyasına yazıldı.")
    else:
        print("[UYARI] Hiçbir link bulunamadı.")

if __name__ == "__main__":
    main()
