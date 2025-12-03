import requests
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

# --- GELİŞMİŞ YAPILANDIRMA ---
AES_KEY_STR = "ywevqtjrurkwtqgz"
USER_AGENT = "speedrestapi"
X_REQUESTED_WITH = "com.bp.box"
REFERER_URL = "https://speedrestapi.com/"
DOMAIN_CERT_URL = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 20  # Aynı anda işlenecek istek sayısı (Hızı artırır)

class CryptoHandler:
    def __init__(self, key_str):
        self.key = key_str.encode('utf-8')
        self.iv = self.key # Smali analizine göre IV ve Key aynı byte dizisi

    def decrypt(self, encrypted_b64):
        try:
            # Padding hatalarını önlemek için güvenli decode
            encrypted_b64 = encrypted_b64.strip()
            # Eksik padding varsa tamamla
            missing_padding = len(encrypted_b64) % 4
            if missing_padding:
                encrypted_b64 += '=' * (4 - missing_padding)
                
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decoded = base64.b64decode(encrypted_b64)
            decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
            return decrypted.decode('utf-8')
        except Exception as e:
            return None

class InatAPI:
    def __init__(self):
        self.crypto = CryptoHandler(AES_KEY_STR)
        self.domain = self.get_current_domain()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-Requested-With": X_REQUESTED_WITH,
            "Referer": REFERER_URL,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        })

    def get_current_domain(self):
        try:
            response = requests.get(DOMAIN_CERT_URL, timeout=10)
            if response.status_code != 200: return None
            
            content = response.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "").strip()
            parts = content.split(':')
            if len(parts) < 2: return None
            
            layer1 = self.crypto.decrypt(parts[0].strip())
            if not layer1: return None
            
            l1_parts = layer1.split(':')
            final_json_str = self.crypto.decrypt(l1_parts[0])
            
            data = json.loads(final_json_str)
            return data.get("DC10", None)
        except:
            return None

    def request_data(self, path_url):
        if not self.domain: return None
        target_url = f"{self.domain}{path_url}" if path_url.startswith("/") else path_url
        
        # Smali analizinden: POST body her zaman 1=[KEY]&0=[KEY]
        payload = f"1={AES_KEY_STR}&0={AES_KEY_STR}"
        
        try:
            response = self.session.post(target_url, data=payload, timeout=10)
            if response.status_code == 200:
                return self.decrypt_response_body(response.text)
        except:
            pass
        return None

    def decrypt_response_body(self, text):
        if not text: return None
        try:
            # Çift katmanlı şifre çözme
            parts = text.split(':')
            layer1 = self.crypto.decrypt(parts[0])
            if not layer1: return None
            
            l1_parts = layer1.split(':')
            final_json = self.crypto.decrypt(l1_parts[0])
            return final_json
        except:
            return None

def process_channel(api, item, category_name):
    """
    Tek bir içeriği işler ve M3U formatına uygun string döndürür.
    Eğer içerik detay isteği gerektiriyorsa (film/dizi) onu da yapar.
    """
    try:
        # İsim ve Resim bilgilerini güvenli al
        name = item.get('chName', item.get('diziName', 'Bilinmeyen İçerik'))
        img = item.get('chImg', item.get('diziImg', ''))
        url = item.get('chUrl', item.get('diziUrl', ''))
        ctype = item.get('chType', item.get('diziType', ''))
        
        final_link = ""

        # Canlı yayın veya doğrudan web linki ise
        if ctype in ['live_url', 'web', 'link']:
            final_link = url
        
        # Dizi veya Film ise (Detay isteği gerekir)
        elif ctype in ['dizi', 'film'] or url.endswith('.php'):
            # Burası 'Derin Tarama' kısmıdır.
            # Uygulama burada parseTvSeriesResponse veya parseMovieResponse çağırır.
            # Biz de aynı URL'ye istek atıp gerçek video linkini arayacağız.
            detail_json = api.request_data(url)
            if detail_json:
                try:
                    # Genellikle detay isteğinden dönen JSON bir liste [] veya obje {} olur.
                    # Eğer liste ise ilk elemana bakarız.
                    if detail_json.startswith('['):
                        det_data = json.loads(detail_json)
                        if len(det_data) > 0:
                            # Sezon/Bölüm mantığı çok karmaşık olduğu için m3u'da
                            # genellikle ilk bulunan oynatılabilir linki veya fragmanı alırız.
                            # Ancak filmler için genellikle tek parça link döner.
                            obj = det_data[0]
                            final_link = obj.get('diziUrl', obj.get('chUrl', ''))
                            # Eğer hala link yoksa ve seasonData varsa, ilk sezon ilk bölüme gidilebilir
                            # ama bu scripti çok yavaşlatır. Şimdilik ana detay linkini alıyoruz.
                    else:
                        det_data = json.loads(detail_json)
                        final_link = det_data.get('diziUrl', det_data.get('chUrl', ''))
                except:
                    pass
        
        # Eğer link bulunduysa M3U formatını oluştur
        if final_link and final_link.startswith("http"):
            entry = f'#EXTINF:-1 tvg-logo="{img}" group-title="{category_name}",{name}\n'
            entry += f'#EXTVLCOPT:http-user-agent={USER_AGENT}\n'
            entry += f'#EXTVLCOPT:http-referrer={REFERER_URL}\n'
            entry += f"{final_link}\n"
            return entry
            
    except Exception as e:
        return None
    return None

def generate_playlist():
    api = InatAPI()
    if not api.domain:
        print("Domain çözülemedi, işlem iptal.")
        return

    print(f"Domain bulundu: {api.domain}")
    
    # Kategorileri Çek
    cat_json = api.request_data("")
    if not cat_json: return

    categories = json.loads(cat_json)
    m3u_entries = []
    
    # ThreadPool ile paralel işlem (Hızlandırma)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_cat = {}
        
        for cat in categories:
            cat_name = cat.get('catName', '')
            cat_url = cat.get('catUrl', '')
            
            # Gereksiz kategorileri atla
            if not cat_url or "Hata" in cat_name or "Destek" in cat_name or "Telegram" in cat_name:
                continue
                
            # Kategori içeriğini çekmek için future oluşturma (burası hala seri olabilir çünkü kategori sayısı az)
            # Ancak kategori içindeki kanalları paralel işleyeceğiz.
            
            print(f"Kategori taranıyor: {cat_name}")
            ch_json = api.request_data(cat_url)
            
            if ch_json:
                try:
                    channels = json.loads(ch_json)
                    # Bu kategorideki her bir kanal/içerik için bir iş parçacığı başlat
                    for item in channels:
                        future = executor.submit(process_channel, api, item, cat_name)
                        future_to_cat[future] = item.get('chName', 'item')
                except:
                    pass

        # Sonuçları topla
        print("İçerikler işleniyor ve linkler çözülüyor...")
        for future in concurrent.futures.as_completed(future_to_cat):
            result = future.result()
            if result:
                m3u_entries.append(result)

    # Dosyayı yaz
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("#EXTM3U\n")
        for entry in m3u_entries:
            f.write(entry)
            
    print(f"Tamamlandı. Toplam {len(m3u_entries)} içerik eklendi.")

if __name__ == "__main__":
    generate_playlist()
