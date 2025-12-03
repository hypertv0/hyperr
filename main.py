import requests
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys

# --- SABİT AYARLAR (Smali kodlarından alındı) ---
STATIC_AES_KEY = "ywevqtjrurkwtqgz"
USER_AGENT = "speedrestapi"
X_REQUESTED_WITH = "com.bp.box"
REFERER_URL = "https://speedrestapi.com/"
DOMAIN_URL = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
FALLBACK_DOMAIN_URL = "https://static.staticsave.com/conn/ct.js"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 25  # Hız için eşzamanlı işlem sayısı

class InatCrypto:
    def __init__(self):
        self.block_size = AES.block_size

    def decrypt_aes(self, encrypted_b64, key_str):
        """
        AES-128-CBC şifre çözme. 
        Smali analizine göre: IV ve Key aynı değerdir.
        """
        try:
            key = key_str.encode('utf-8')
            iv = key # Uygulamada IV, Key ile aynı byte dizisidir.
            
            # Base64 padding düzeltme
            encrypted_b64 = encrypted_b64.strip()
            missing_padding = len(encrypted_b64) % 4
            if missing_padding:
                encrypted_b64 += '=' * (4 - missing_padding)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decoded_data = base64.b64decode(encrypted_b64)
            decrypted_data = unpad(cipher.decrypt(decoded_data), self.block_size)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            # Şifre çözme hatalarını sessizce geç, veri bozuk olabilir
            return None

class InatBoxAPI:
    def __init__(self):
        self.crypto = InatCrypto()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-Requested-With": X_REQUESTED_WITH,
            "Referer": REFERER_URL,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        })
        self.base_domain = self.resolve_domain()

    def resolve_domain(self):
        """
        InatBox.kt -> getDomain mantığının birebir aynısı.
        1. Dosyayı indir.
        2. ':' ile böl. (ŞifreliVeri : Anahtar)
        3. Çöz -> Çıkan sonucu tekrar ':' ile böl.
        4. Tekrar Çöz -> JSON içinden DC10'u al.
        """
        print("[-] Domain çözümleniyor...")
        
        # 1. Yöntem: Client.pem
        try:
            r = self.session.get(DOMAIN_URL, timeout=10)
            if r.status_code == 200:
                raw = r.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").strip()
                parts = raw.split(':')
                if len(parts) >= 2:
                    cipher_text = parts[0].strip()
                    dynamic_key = parts[1].strip()
                    
                    # Katman 1 Çözme
                    layer1 = self.crypto.decrypt_aes(cipher_text, dynamic_key)
                    if layer1:
                        l1_parts = layer1.split(':')
                        if len(l1_parts) >= 2:
                            # Katman 2 Çözme
                            final_json = self.crypto.decrypt_aes(l1_parts[0], l1_parts[1])
                            if final_json:
                                data = json.loads(final_json)
                                domain = data.get("DC10")
                                if domain:
                                    print(f"[+] Domain bulundu (Client.pem): {domain}")
                                    return domain
        except Exception as e:
            print(f"[!] Client.pem hatası: {e}")

        # 2. Yöntem: Fallback (ct.js)
        try:
            r = self.session.get(FALLBACK_DOMAIN_URL, timeout=10)
            if r.status_code == 200:
                content = r.text.strip()
                # Bazen direkt URL yazar, bazen şifrelidir.
                if content.startswith("http"):
                    print(f"[+] Domain bulundu (Fallback): {content}")
                    return content
        except Exception as e:
            print(f"[!] Fallback hatası: {e}")

        return None

    def get_data(self, path=""):
        """
        Sunucudan veriyi çeker ve çift katmanlı şifresini çözer.
        Smali: makeInatRequest -> getJsonFromEncryptedInatResponse
        """
        if not self.base_domain: return None
        
        url = f"{self.base_domain}{path}" if path.startswith("/") else f"{self.base_domain}/{path}"
        # Anahtar statiktir: ywevqtjrurkwtqgz
        payload = f"1={STATIC_AES_KEY}&0={STATIC_AES_KEY}"
        
        try:
            resp = self.session.post(url, data=payload, timeout=15)
            if resp.status_code != 200: return None
            
            # Yanıt şifreli gelir: ŞifreliVeri:ŞifreliVeri...
            # Ancak API yanıtlarında anahtar her zaman STATIC_AES_KEY'dir.
            # 1. Katman Çözme
            parts = resp.text.split(':')
            layer1 = self.crypto.decrypt_aes(parts[0], STATIC_AES_KEY)
            if not layer1: return None
            
            # 2. Katman Çözme
            l1_parts = layer1.split(':')
            final_json = self.crypto.decrypt_aes(l1_parts[0], STATIC_AES_KEY)
            
            if final_json:
                return json.loads(final_json)
        except Exception:
            return None
        return None

def process_item(api, item, category_title):
    """
    Tek bir içeriği işler ve M3U formatına çevirir.
    Eğer içerik bir Dizi/Film ise detayına girer (Derin Tarama).
    """
    try:
        name = item.get('chName', item.get('diziName', 'Bilinmeyen'))
        img = item.get('chImg', item.get('diziImg', ''))
        url = item.get('chUrl', item.get('diziUrl', ''))
        ctype = item.get('chType', item.get('diziType', ''))
        
        stream_url = ""

        # Canlı Yayınlar ve Web Linkleri (Genelde direkt linktir)
        if ctype in ['live_url', 'web', 'link', 'tekli_regex_lb_sh_3']:
            stream_url = url
        
        # Dizi veya Film ise Detay İsteği At (Deep Crawl)
        # InatBox mantığı: Kategori -> Liste -> Tıklayınca Detay İsteği -> Video Linki
        elif ctype in ['dizi', 'film'] or (url and url.endswith('.php')):
            try:
                # Detay verisini çek
                detail_data = api.get_data(url)
                if detail_data:
                    # Dönen veri liste ise (örn: [ {film_detayları} ])
                    if isinstance(detail_data, list) and len(detail_data) > 0:
                        obj = detail_data[0]
                        stream_url = obj.get('diziUrl', obj.get('chUrl', ''))
                    # Dönen veri obje ise
                    elif isinstance(detail_data, dict):
                        stream_url = detail_data.get('diziUrl', detail_data.get('chUrl', ''))
            except:
                pass

        # Link geçerli mi kontrol et ve temizle
        if stream_url and stream_url.startswith("http"):
            # Yandex Disk veya VK linklerini ele (Otomatik oynatılamazlar)
            if "yandex" in stream_url or "vk.com" in stream_url:
                return None
            
            # M3U Entry Oluştur
            entry = f'#EXTINF:-1 tvg-logo="{img}" group-title="{category_title}",{name}\n'
            # Bazı playerlar için gerekli headerlar
            entry += f'#EXTVLCOPT:http-user-agent={USER_AGENT}\n'
            entry += f'#EXTVLCOPT:http-referrer={REFERER_URL}\n'
            entry += f"{stream_url}\n"
            return entry

    except Exception:
        pass
    return None

def main():
    api = InatBoxAPI()
    if not api.base_domain:
        print("[!] Domain bulunamadığı için işlem durduruldu.")
        sys.exit(1)

    print("[-] Kategoriler çekiliyor...")
    categories = api.get_data("") # Ana istek
    
    if not categories:
        print("[!] Kategori listesi alınamadı.")
        sys.exit(1)

    print(f"[-] {len(categories)} kategori bulundu. Tarama başlıyor...")
    
    m3u_entries = []
    
    # ThreadPool ile çoklu iş parçacığı (Hızlandırma)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {}
        
        for cat in categories:
            cat_name = cat.get('catName', 'Genel')
            cat_url = cat.get('catUrl', '')
            
            # Gereksiz kategorileri filtrele
            if not cat_url or any(x in cat_name for x in ["Hata", "Destek", "Telegram", "Duyuru"]):
                continue
            
            print(f"   > Kategori taranıyor: {cat_name}")
            
            # Kategori içeriğini çek
            channels = api.get_data(cat_url)
            
            if channels and isinstance(channels, list):
                for ch in channels:
                    # Her bir içerik için iş parçacığı başlat
                    future = executor.submit(process_item, api, ch, cat_name)
                    future_map[future] = ch.get('chName', 'item')

        # Sonuçları topla
        print("[-] İçerik detayları taranıyor (Bu biraz sürebilir)...")
        completed = 0
        total = len(future_map)
        
        for future in concurrent.futures.as_completed(future_map):
            result = future.result()
            if result:
                m3u_entries.append(result)
            completed += 1
            if completed % 50 == 0:
                print(f"    İlerleme: {completed}/{total}")

    # Dosyayı kaydet
    if m3u_entries:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in m3u_entries:
                f.write(entry)
        print(f"[SUCCESS] {OUTPUT_FILE} oluşturuldu! Toplam {len(m3u_entries)} içerik.")
    else:
        print("[!] Hiçbir oynatılabilir içerik bulunamadı.")

if __name__ == "__main__":
    main()
