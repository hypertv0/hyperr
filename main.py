import requests
import json
import base64
import concurrent.futures
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
import re

# --- GELİŞMİŞ YAPILANDIRMA ---
AES_KEY_STR = "ywevqtjrurkwtqgz"
USER_AGENT = "speedrestapi"
X_REQUESTED_WITH = "com.bp.box"
REFERER_URL = "https://speedrestapi.com/"
# Birincil kaynak (Şifreli)
DOMAIN_CERT_URL = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
# İkincil kaynak (Yedek - Genellikle gerçek domain burada yazar)
FALLBACK_URL = "https://static.staticsave.com/conn/ct.js"
OUTPUT_FILE = "playlist.m3u"
MAX_WORKERS = 20

class CryptoHandler:
    def __init__(self, key_str):
        self.key = key_str.encode('utf-8')
        self.iv = self.key

    def decrypt(self, encrypted_b64):
        try:
            encrypted_b64 = encrypted_b64.strip()
            # Padding düzeltme
            pad = len(encrypted_b64) % 4
            if pad:
                encrypted_b64 += '=' * (4 - pad)
                
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decoded = base64.b64decode(encrypted_b64)
            decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
            return decrypted.decode('utf-8')
        except Exception as e:
            return None

class InatAPI:
    def __init__(self):
        self.crypto = CryptoHandler(AES_KEY_STR)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "X-Requested-With": X_REQUESTED_WITH,
            "Referer": REFERER_URL,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        })
        self.domain = self.find_real_domain()

    def find_real_domain(self):
        """
        Gerçek API domainini bulmak için önce client.pem'i dener,
        olmazsa ct.js'nin İÇERİĞİNİ okur.
        """
        print("Domain aranıyor...")
        
        # YÖNTEM 1: client.pem çözme
        try:
            response = requests.get(DOMAIN_CERT_URL, timeout=10)
            if response.status_code == 200:
                content = response.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "").strip()
                parts = content.split(':')
                if len(parts) >= 2:
                    layer1 = self.crypto.decrypt(parts[0].strip())
                    if layer1:
                        l1_parts = layer1.split(':')
                        final_json_str = self.crypto.decrypt(l1_parts[0])
                        data = json.loads(final_json_str)
                        domain = data.get("DC10", None)
                        if domain and "http" in domain:
                            print(f"Domain bulundu (Yöntem 1): {domain}")
                            return domain
        except Exception as e:
            print(f"Yöntem 1 hatası: {e}")

        # YÖNTEM 2: Fallback URL'nin İÇERİĞİNİ okuma (Düzeltilen Kısım)
        print("Yöntem 1 başarısız, Yöntem 2 (Fallback) deneniyor...")
        try:
            response = requests.get(FALLBACK_URL, timeout=10)
            if response.status_code == 200:
                # Gelen veriyi analiz et
                content = response.text.strip()
                
                # Eğer JSON ise {"DC10": "..."} formatını ara
                try:
                    data = json.loads(content)
                    if "DC10" in data:
                        domain = data["DC10"]
                        print(f"Domain bulundu (Yöntem 2 JSON): {domain}")
                        return domain
                except:
                    pass
                
                # Eğer düz metin http... ise
                if content.startswith("http"):
                    print(f"Domain bulundu (Yöntem 2 Text): {content}")
                    return content
                
                # Eğer şifreliyse çözmeyi dene (AES)
                decrypted = self.crypto.decrypt(content)
                if decrypted and "http" in decrypted:
                     # Bazen decrypt edilen veri JSON olabilir
                    try:
                        jdata = json.loads(decrypted)
                        if "DC10" in jdata: return jdata["DC10"]
                    except:
                        if decrypted.startswith("http"): return decrypted

        except Exception as e:
            print(f"Yöntem 2 hatası: {e}")

        print("KRİTİK HATA: Hiçbir domain bulunamadı!")
        return None

    def request_data(self, path_url):
        if not self.domain: return None
        # URL birleştirme güvenliği
        base = self.domain.rstrip('/')
        path = path_url.lstrip('/')
        target_url = f"{base}/{path}"
        
        payload = f"1={AES_KEY_STR}&0={AES_KEY_STR}"
        
        try:
            # Domain static file ise POST atma (Hata önleyici)
            if target_url.endswith(".js") or target_url.endswith(".pem"):
                return None

            response = self.session.post(target_url, data=payload, timeout=15)
            if response.status_code == 200:
                return self.decrypt_response_body(response.text)
            else:
                print(f"İstek başarısız ({response.status_code}): {target_url}")
        except Exception as e:
            # print(f"Bağlantı hatası: {e}") 
            pass
        return None

    def decrypt_response_body(self, text):
        if not text: return None
        try:
            parts = text.split(':')
            layer1 = self.crypto.decrypt(parts[0])
            if not layer1: return None
            
            l1_parts = layer1.split(':')
            final_json = self.crypto.decrypt(l1_parts[0])
            return final_json
        except:
            return None

def process_channel(api, item, category_name):
    try:
        name = item.get('chName', item.get('diziName', 'Bilinmeyen'))
        img = item.get('chImg', item.get('diziImg', ''))
        url = item.get('chUrl', item.get('diziUrl', ''))
        ctype = item.get('chType', item.get('diziType', ''))
        
        final_link = ""

        # Canlı yayın veya doğrudan link
        if ctype in ['live_url', 'web', 'link']:
            final_link = url
        
        # Dizi/Film için detay sorgusu (Deep Crawl)
        elif (ctype in ['dizi', 'film'] or url.endswith('.php')) and api.domain:
            # URL zaten tam http içeriyorsa domain ekleme
            req_url = url if url.startswith("http") else url
            
            detail_json = api.request_data(req_url)
            if detail_json:
                try:
                    if detail_json.startswith('['):
                        det_data = json.loads(detail_json)
                        if len(det_data) > 0:
                            obj = det_data[0]
                            final_link = obj.get('diziUrl', obj.get('chUrl', ''))
                    else:
                        det_data = json.loads(detail_json)
                        final_link = det_data.get('diziUrl', det_data.get('chUrl', ''))
                except:
                    pass
        
        # Link düzeltmeleri
        if final_link:
            # Yandex veya VK linklerini pas geç (M3U'da çalışmazlar)
            if "yandex" in final_link or "vk.com" in final_link:
                return None
                
            # Göreceli linkleri tamamlama (nadiren olur ama olsun)
            if not final_link.startswith("http") and not final_link.startswith("rtmp"):
                 final_link = f"{api.domain.rstrip('/')}/{final_link.lstrip('/')}"

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
        print("İşlem durduruldu: Domain yok.")
        return
    
    print("Kategoriler çekiliyor...")
    cat_json = api.request_data("") # Ana sayfaya boş istek atılır
    
    if not cat_json: 
        print("Kategori verisi alınamadı (Boş yanıt).")
        return

    try:
        categories = json.loads(cat_json)
    except:
        print("Kategori JSON formatı hatalı.")
        return

    m3u_entries = []
    
    print(f"Toplam {len(categories)} kategori bulundu. Tarama başlıyor (Max 20 Worker)...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_cat = {}
        
        for cat in categories:
            cat_name = cat.get('catName', 'Genel')
            cat_url = cat.get('catUrl', '')
            
            if not cat_url or any(x in cat_name for x in ["Hata", "Destek", "Telegram", "Duyuru"]):
                continue
            
            print(f"> {cat_name} taranıyor...")
            ch_json = api.request_data(cat_url)
            
            if ch_json:
                try:
                    channels = json.loads(ch_json)
                    for item in channels:
                        future = executor.submit(process_channel, api, item, cat_name)
                        future_to_cat[future] = item.get('chName', 'item')
                except:
                    pass

        completed_count = 0
        total_futures = len(future_to_cat)
        
        for future in concurrent.futures.as_completed(future_to_cat):
            result = future.result()
            if result:
                m3u_entries.append(result)
            
            completed_count += 1
            if completed_count % 50 == 0:
                print(f"İlerleme: {completed_count}/{total_futures} içerik işlendi.")

    if m3u_entries:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("#EXTM3U\n")
            for entry in m3u_entries:
                f.write(entry)
        print(f"BAŞARILI: {OUTPUT_FILE} oluşturuldu. Toplam {len(m3u_entries)} kanal/film.")
    else:
        print("UYARI: Hiçbir içerik bulunamadı vey
