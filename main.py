import requests
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import sys
import re

# --- SABİTLER (Smali analizinden) ---
STATIC_AES_KEY = "ywevqtjrurkwtqgz"
USER_AGENT = "speedrestapi"
X_REQUESTED_WITH = "com.bp.box"
REFERER_URL = "https://speedrestapi.com/"

# Domain Kaynakları
PRIMARY_CERT_URL = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
FALLBACK_URL = "https://static.staticsave.com/conn/ct.js"

OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 20  # Hız için thread sayısı

class InatCrypto:
    def __init__(self):
        self.block_size = AES.block_size

    def decrypt(self, encrypted_text, key_text):
        """
        Smali: InatBoxModelsKt.decryptAES
        Mantık: AES-128-CBC, Key = text.bytes, IV = text.bytes (Key ve IV aynı)
        """
        try:
            if not encrypted_text or not key_text: return None
            
            # Key ve IV hazırlığı
            key = key_text.encode('utf-8')
            iv = key # Uygulama mantığında IV, Key ile aynıdır.
            
            # Base64 Padding Düzeltme (Eksik karakter varsa tamamla)
            encrypted_text = encrypted_text.strip()
            missing_padding = len(encrypted_text) % 4
            if missing_padding:
                encrypted_text += '=' * (4 - missing_padding)
            
            # Deşifreleme
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decoded_b64 = base64.b64decode(encrypted_text)
            decrypted_bytes = unpad(cipher.decrypt(decoded_b64), self.block_size)
            
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            # print(f"Decrypt Error: {e}") # Hata ayıklama için açılabilir
            return None

class InatDomainResolver:
    def __init__(self, session, crypto):
        self.session = session
        self.crypto = crypto

    def resolve(self):
        """Domain bulmak için sırasıyla yöntemleri dener."""
        domain = self._try_client_pem()
        if domain: return domain
        
        domain = self._try_fallback_ct_js()
        if domain: return domain
        
        return None

    def _try_client_pem(self):
        """
        Smali: InatBox$Companion$getDomain$1
        Karmaşık çift katmanlı şifre çözme.
        """
        print("[-] Yöntem 1 (Client.pem) deneniyor...")
        try:
            r = self.session.get(PRIMARY_CERT_URL, timeout=10)
            if r.status_code != 200: return None

            raw = r.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "").strip()
            parts = raw.split(':')
            
            # Format: ŞifreliData : DinamikKey
            if len(parts) < 2: return None
            
            cipher_text = parts[0]
            dynamic_key = parts[1]

            # Katman 1 Çözme
            layer1 = self.crypto.decrypt(cipher_text, dynamic_key)
            if not layer1: return None

            # Katman 2 Çözme (Layer1 formatı: ŞifreliData : StaticKey2)
            l1_parts = layer1.split(':')
            if len(l1_parts) < 2: return None
            
            final_json_str = self.crypto.decrypt(l1_parts[0], l1_parts[1])
            if not final_json_str: return None

            # JSON parse et ve DC10'u al
            data = json.loads(final_json_str)
            return data.get("DC10")
        except Exception as e:
            print(f"[!] Yöntem 1 Hatası: {e}")
            return None

    def _try_fallback_ct_js(self):
        """
        Smali: Fallback URL. Genellikle düz metin veya basit şifreli domain içerir.
        """
        print("[-] Yöntem 2 (Fallback ct.js) deneniyor...")
        try:
            r = self.session.get(FALLBACK_URL, timeout=10)
            if r.status_code != 200: return None
            
            content = r.text.strip()
            
            # Olasılık 1: Direkt URL (http...)
            if content.startswith("http"):
                print(f"[+] Domain düz metin olarak bulundu: {content}")
                return content
            
            # Olasılık 2: JSON {"DC10": "..."}
            try:
                jdata = json.loads(content)
                if "DC10" in jdata: return jdata["DC10"]
            except:
                pass
            
            # Olasılık 3: Şifreli metin (Statik key ile çöz)
            decrypted = self.crypto.decrypt(content, STATIC_AES_KEY)
            if decrypted and decrypted.startswith("http"):
                print(f"[+] Domain şifreli içerikten çözüldü: {decrypted}")
                return decrypted
                
            # Olasılık 4: Şifreli JSON
            if decrypted:
                try:
                    jdata = json.loads(decrypted)
                    if "DC10" in jdata: return jdata["DC10"]
                except:
                    pass

        except Exception as e:
            print(f"[!] Yöntem 2 Hatası: {e}")
        
        return None

class InatBoxProcessor:
    def __init__(self):
        self.crypto = InatCrypto()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-Requested-With": X_REQUESTED_WITH,
            "Referer": REFERER_URL,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        })
        
        resolver = InatDomainResolver(self.session, self.crypto)
        self.base_url = resolver.resolve()
        
        if self.base_url:
            # URL sonundaki slash'i temizle
            self.base_url = self.base_url.rstrip('/')

    def request_api(self, path=""):
        """
        API'ye istek atar ve yanıtı çözer.
        Smali: makeInatRequest -> 1=[KEY]&0=[KEY]
        """
        if not self.base_url: return None
        
        target_url = f"{self.base_url}/{path.lstrip('/')}"
        payload = f"1={STATIC_AES_KEY}&0={STATIC_AES_KEY}"
        
        try:
            resp = self.session.post(target_url, data=payload, timeout=15)
            if resp.status_code != 200: return None
            
            # Yanıt formatı: ŞifreliVeri : ...
            parts = resp.text.split(':')
            if len(parts) < 1: return None
            
            # Katman 1
            layer1 = self.crypto.decrypt(parts[0], STATIC_AES_KEY)
            if not layer1: return None
            
            # Katman 2
            l1_parts = layer1.split(':')
            final_json = self.crypto.decrypt(l1_parts[0], STATIC_AES_KEY)
            
            return json.loads(final_json)
        except Exception:
            return None

    def crawl_content(self, item, category_name):
        """
        İçerik öğesini analiz eder ve M3U satırı oluşturur.
        Diziler ve filmler için detay isteği atar.
        """
        try:
            name = item.get('chName', item.get('diziName', 'Bilinmeyen İçerik'))
            img = item.get('chImg', item.get('diziImg', ''))
            url = item.get('chUrl', item.get('diziUrl', ''))
            ctype = item.get('chType', item.get('diziType', ''))
            
            final_url = ""

            # 1. Tip: Direkt Linkler (Canlı TV vb.)
            if ctype in ['live_url', 'web', 'link', 'tekli_regex_lb_sh_3']:
                final_url = url
            
            # 2. Tip: Detay İsteği Gerektirenler (Film/Dizi)
            elif ctype in ['dizi', 'film'] or (url and url.endswith('.php')):
                # Detay sorgusu yap
                details = self.request_api(url)
                if details:
                    # Dönen veri liste ise ilk elemanı al
                    if isinstance(details, list) and len(details) > 0:
                        final_url = details[0].get('diziUrl', details[0].get('chUrl', ''))
                    # Obje ise direkt al
                    elif isinstance(details, dict):
                        final_url = details.get('diziUrl', details.get('chUrl', ''))

            # Link doğrulama ve formatlama
            if final_url and final_url.startswith("http"):
                # Desteklenmeyen kaynakları filtrele (M3U playerlar Yandex/VK açamaz)
                if "yandex" in final_url or "vk.com" in final_url or "drive.google" in final_url:
                    return None
                
                # M3U Entry
                entry = f'#EXTINF:-1 tvg-logo="{img}" group-title="{category_name}",{name}\n'
                entry += f'#EXTVLCOPT:http-user-agent={USER_AGENT}\n'
                entry += f'#EXTVLCOPT:http-referrer={REFERER_URL}\n'
                entry += f"{final_url}\n"
                return entry
                
        except Exception:
            pass
        return None

def main():
    processor = InatBoxProcessor()
    
    if not processor.base_url:
        print("[!!!] Domain bulunamadı. Script sonlandırılıyor.")
        sys.exit(1)
        
    print(f"[OK] Aktif Domain: {processor.base_url}")
    print("[-] Kategoriler çekiliyor...")
    
    categories = processor.request_api("") # Root isteği kategorileri getirir
    
    if not categories:
        print("[!!!] Kategori listesi alınamadı.")
        sys.exit(1)

    m3u_list = []
    
    # ThreadPoolExecutor ile Hızlı Tarama
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        
        for cat in categories:
            cat_name = cat.get('catName', 'Genel')
            cat_url = cat.get('catUrl', '')
            
            # Filtreler
            if not cat_url or any(x in cat_name for x in ["Hata", "Destek", "Telegram", "Duyuru"]):
                continue
                
            print(f"   > Kategori Taranıyor: {cat_name}")
            
            # Kategori içeriğini çek
            channels = processor.request_api(cat_url)
            
            if channels and isinstance(channels, list):
                for item in channels:
                    # Her içerik için bir iş parçacığı başlat
                    ft = executor.submit(processor.crawl_content, item, cat_name)
                    futures[ft] = item.get('chName', 'item')
        
        print(f"[-] Toplam {len(futures)} içerik işleniyor...")
        
        count = 0
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                m3u_list.append(res)
            count += 1
            if count % 50 == 0:
                print(f"    İlerleme: {count}/{len(futures)}")

    # Dosyayı Yaz
    if m3u_list:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for line in m3u_list:
                f.write(line)
        print(f"[TAMAMLANDI] {OUTPUT_FILE} oluşturuldu. Toplam kanal/film: {len(m3u_list)}")
    else:
        print("[UYARI] M3U listesi boş.")

if __name__ == "__main__":
    main()
