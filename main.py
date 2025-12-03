import requests
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys
import urllib3

# SSL Uyarılarını Kapat (HTTPS sertifika hatalarını yoksaymak için)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- YAPILANDIRMA ---
# Smali kodundaki InatBox.kt'den alınan sabit anahtar
STATIC_AES_KEY = "ywevqtjrurkwtqgz"

# Android cihaz taklidi yapan başlıklar
HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 10; SM-G973F Build/QP1A.190711.020)",
    "X-Requested-With": "com.bp.box",
    "Referer": "https://speedrestapi.com/",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Accept": "*/*"
}

# Eklentideki Kaynaklar
URL_CLIENT_PEM = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
URL_CT_JS = "https://static.staticsave.com/conn/ct.js"

OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 25

class CryptoUtils:
    """Smali kodundaki InatBoxModelsKt.decryptAES fonksiyonunun Python karşılığı"""
    def __init__(self):
        self.block_size = AES.block_size

    def decrypt(self, encrypted_text, key_text):
        try:
            if not encrypted_text or not key_text: return None
            
            # Key ve IV aynıdır (Smali analizinden)
            key_bytes = key_text.encode('utf-8')
            iv_bytes = key_bytes 
            
            # Base64 hatalarını toleranslı karşıla
            encrypted_text = encrypted_text.strip().replace('\n', '').replace('\r', '')
            pad = len(encrypted_text) % 4
            if pad: encrypted_text += '=' * (4 - pad)
            
            # Şifreyi çöz
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            decoded = base64.b64decode(encrypted_text)
            decrypted_raw = cipher.decrypt(decoded)
            
            # Padding'i kaldır
            try:
                return unpad(decrypted_raw, self.block_size).decode('utf-8')
            except:
                # Padding bozuksa bile veriyi kurtarmaya çalış
                return decrypted_raw.decode('utf-8', errors='ignore').strip()
        except:
            return None

class DomainFinder:
    """Sunucu adresini bulan sınıf"""
    def __init__(self, session, crypto):
        self.session = session
        self.crypto = crypto

    def check_api_validity(self, domain):
        """Bir domainin geçerli Inat API olup olmadığını test eder"""
        # Http ve Https olarak dene
        protocols = [domain] if domain.startswith("http") else [f"https://{domain}", f"http://{domain}"]
        
        for url in protocols:
            clean_url = url.rstrip('/')
            try:
                # API'ye boş istek atarak test et (Kategorileri döndürmeli)
                payload = f"1={STATIC_AES_KEY}&0={STATIC_AES_KEY}"
                r = self.session.post(f"{clean_url}/", data=payload, timeout=4, verify=False)
                
                # Eğer yanıt şifreliyse (:) veya JSON ise ({) bu doğru sunucudur
                if r.status_code == 200 and (":" in r.text or "chName" in r.text):
                    return clean_url
            except:
                continue
        return None

    def get_domain(self):
        # 1. Yöntem: Client.pem (Uygulamanın varsayılanı)
        print("[-] Yöntem 1: Statik Dosya (Client.pem) kontrol ediliyor...")
        try:
            r = self.session.get(URL_CLIENT_PEM, timeout=5, verify=False)
            if r.status_code == 200:
                data = r.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
                parts = data.split(':')
                if len(parts) >= 2:
                    # Çift katmanlı şifre çözme
                    l1 = self.crypto.decrypt(parts[0], parts[1])
                    if l1:
                        p2 = l1.split(':')
                        final = self.crypto.decrypt(p2[0], p2[1])
                        js = json.loads(final)
                        if "DC10" in js:
                            valid = self.check_api_validity(js["DC10"])
                            if valid: return valid
        except Exception as e:
            print(f"    Hata: {e}")

        # 2. Yöntem: ct.js (Uygulamanın yedeği)
        print("[-] Yöntem 2: Yedek Dosya (ct.js) kontrol ediliyor...")
        try:
            r = self.session.get(URL_CT_JS, timeout=5, verify=False)
            if r.status_code == 200:
                content = r.text.strip()
                # İçeriği direkt test et
                valid = self.check_api_validity(content)
                if valid: return valid
                
                # Şifreliyse çözüp test et
                dec = self.crypto.decrypt(content, STATIC_AES_KEY)
                if dec:
                    valid = self.check_api_validity(dec)
                    if valid: return valid
        except Exception as e:
            print(f"    Hata: {e}")

        # 3. Yöntem: BRUTE FORCE (GitHub IP'si engelliyse bu çalışır)
        print("[-] Yöntem 3: Akıllı Tarama (Brute Force) başlatılıyor...")
        
        # 125'ten 160'a kadar olası adresleri üret
        candidates = []
        for i in range(130, 160):
            candidates.append(f"inattv{i}.xyz")
            candidates.append(f"inattv{i}.link")
            candidates.append(f"inattv{i}.com")
            candidates.append(f"inattv{i}.cf")

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(self.check_api_validity, domain) for domain in candidates]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    print(f"[!!!] Sunucu Bulundu: {result}")
                    executor.shutdown(wait=False) # Diğerlerini durdur
                    return result
        
        return None

class InatCrawler:
    def __init__(self):
        self.crypto = CryptoUtils()
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        
        finder = DomainFinder(self.session, self.crypto)
        self.base_url = finder.get_domain()

    def api_post(self, path=""):
        """API'ye POST isteği atar ve yanıtı çözer"""
        if not self.base_url: return None
        
        url = f"{self.base_url}/{path.lstrip('/')}"
        data = f"1={STATIC_AES_KEY}&0={STATIC_AES_KEY}"
        
        try:
            # İstek at
            r = self.session.post(url, data=data, timeout=15, verify=False)
            if r.status_code != 200: return None
            
            text = r.text
            
            # Şifreli Yanıt (Data:Key formatı)
            if ":" in text:
                parts = text.split(':')
                if len(parts) < 1: return None
                
                # Katman 1
                l1 = self.crypto.decrypt(parts[0], STATIC_AES_KEY)
                if not l1: return None
                
                # Katman 2 (Genellikle ':' ile ayrılır)
                l1_parts = l1.split(':')
                final_str = self.crypto.decrypt(l1_parts[0], STATIC_AES_KEY) if len(l1_parts) > 0 else l1
                
                if final_str:
                    # Bazen JSON string bozuk olabilir, temizle
                    final_str = final_str.strip()
                    # Eğer liste değilse ve başında { yoksa hata olabilir
                    if final_str.startswith("{") or final_str.startswith("["):
                        return json.loads(final_str)
                        
            # Şifresiz Yanıt
            elif text.startswith("{") or text.startswith("["):
                return json.loads(text)
                
        except Exception:
            pass
        return None

    def process_item(self, item, category):
        """İçeriği M3U formatına çevirir"""
        try:
            name = item.get('chName', item.get('diziName', 'Bilinmeyen'))
            img = item.get('chImg', item.get('diziImg', ''))
            url = item.get('chUrl', item.get('diziUrl', ''))
            ctype = item.get('chType', item.get('diziType', ''))
            
            stream_url = ""

            # Canlı TV veya Web Linki (Direkt alınır)
            if ctype in ['live_url', 'web', 'link', 'tekli_regex_lb_sh_3']:
                stream_url = url
            
            # Film/Dizi (Detay isteği gerekir - Deep Crawl)
            elif ctype in ['dizi', 'film'] or (url and url.endswith('.php')):
                try:
                    details = self.api_post(url)
                    if details:
                        if isinstance(details, list) and details:
                            stream_url = details[0].get('diziUrl', details[0].get('chUrl', ''))
                        elif isinstance(details, dict):
                            stream_url = details.get('diziUrl', details.get('chUrl', ''))
                except: pass

            # Link Kontrolü
            if stream_url and stream_url.startswith("http"):
                # Otomatik oynatılamayan kaynakları (Yandex, VK vb.) ele
                if any(bad in stream_url for bad in ["yandex", "vk.com", "drive.google", "cloud.mail.ru"]):
                    return None
                
                # URL encoding (boşluk varsa)
                stream_url = stream_url.replace(" ", "%20")

                # M3U Entry
                m3u = f'#EXTINF:-1 tvg-logo="{img}" group-title="{category}",{name}\n'
                m3u += f'#EXTVLCOPT:http-user-agent={HEADERS["User-Agent"]}\n'
                m3u += f'#EXTVLCOPT:http-referrer={HEADERS["Referer"]}\n'
                m3u += f"{stream_url}\n"
                return m3u

        except:
            pass
        return None

def main():
    crawler = InatCrawler()
    
    if not crawler.base_url:
        print("[FATAL] Hiçbir sunucu bulunamadı. IP bloğu veya sunucu hatası.")
        sys.exit(1)
        
    print(f"[-] Kategoriler çekiliyor ({crawler.base_url})...")
    cats = crawler.api_post("")
    
    if not cats:
        print("[FATAL] Kategori listesi boş. Şifre çözme hatası olabilir.")
        sys.exit(1)
        
    print(f"[-] {len(cats)} kategori bulundu. İçerikler taranıyor...")
    
    playlist_entries = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for cat in cats:
            c_name = cat.get('catName', 'Genel')
            c_url = cat.get('catUrl', '')
            
            if not c_url or any(x in c_name for x in ["Hata", "Destek", "Telegram", "Duyuru"]):
                continue
            
            print(f"   > Taranıyor: {c_name}")
            items = crawler.api_post(c_url)
            
            if items and isinstance(items, list):
                for item in items:
                    futures.append(executor.submit(crawler.process_item, item, c_name))
        
        print(f"[-] {len(futures)} içerik işleniyor. Lütfen bekleyin...")
        
        count = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: playlist_entries.append(res)
            count += 1
            if count % 50 == 0: print(f"    İşlenen: {count}/{len(futures)}")

    if playlist_entries:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in playlist_entries:
                f.write(entry)
        print(f"\n[BAŞARILI] Liste oluşturuldu: {OUTPUT_FILE} ({len(playlist_entries)} içerik)")
    else:
        print("\n[UYARI] Hiçbir içerik bulunamadı.")

if __name__ == "__main__":
    main()
