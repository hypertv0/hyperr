import requests
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time

# --- YAPILANDIRMA ---
AES_KEY_STR = "ywevqtjrurkwtqgz"
USER_AGENT = "speedrestapi"
X_REQUESTED_WITH = "com.bp.box"
REFERER = "https://speedrestapi.com/"
DOMAIN_CERT_URL = "https://prod-eu-central.pages.dev/a03c6a7ae48351c6408e00c8159e6e64/certificates/client.pem"
OUTPUT_FILE = "playlist.m3u"

class InatDecryptor:
    def __init__(self, key_str):
        self.key = key_str.encode('utf-8')
        self.iv = self.key  # Smali kodunda IV, Key ile aynı byte dizisi olarak kullanılmış

    def decrypt(self, encrypted_b64):
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            decoded = base64.b64decode(encrypted_b64)
            decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
            return decrypted.decode('utf-8')
        except Exception as e:
            # Padding hatalarını yutabiliriz, bazen kirli veri gelebilir
            return None

def get_current_domain():
    try:
        decryptor = InatDecryptor(AES_KEY_STR)
        response = requests.get(DOMAIN_CERT_URL)
        if response.status_code != 200:
            return None
        
        # Sertifika taglerini temizle
        content = response.text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "").strip()
        
        # Smali analizine göre domain çözme mantığı:
        # Metin ':' ile bölünür. İlk parça şifreli metin, ikinci parça anahtar (burada hardcoded anahtarı kullanacağız)
        parts = content.split(':')
        if len(parts) < 2: return None
        
        encrypted_part = parts[0].strip()
        # İlk katman çözme
        layer1 = decryptor.decrypt(encrypted_part)
        if not layer1: return None
        
        # İkinci katman çözme
        l1_parts = layer1.split(':')
        final_json_str = decryptor.decrypt(l1_parts[0])
        
        data = json.loads(final_json_str)
        return data.get("DC10", None) # Smali kodunda DC10 domaini veriyor
    except Exception as e:
        print(f"Domain error: {e}")
        return None

def make_inat_request(base_url, path_url):
    target_url = f"{base_url}{path_url}" if path_url.startswith("/") else path_url
    
    headers = {
        "User-Agent": USER_AGENT,
        "X-Requested-With": X_REQUESTED_WITH,
        "Referer": REFERER,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
    }
    
    # Smali: 1=KEY&0=KEY
    data = f"1={AES_KEY_STR}&0={AES_KEY_STR}"
    
    try:
        response = requests.post(target_url, headers=headers, data=data)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return None

def decrypt_response(response_text):
    if not response_text: return None
    decryptor = InatDecryptor(AES_KEY_STR)
    
    # Çift katmanlı şifre çözme (InatBox.smali -> getJsonFromEncryptedInatResponse)
    try:
        # Katman 1
        parts = response_text.split(':')
        layer1 = decryptor.decrypt(parts[0])
        if not layer1: return None
        
        # Katman 2
        l1_parts = layer1.split(':')
        final_json = decryptor.decrypt(l1_parts[0])
        return final_json
    except:
        return None

def generate_m3u():
    domain = get_current_domain()
    if not domain:
        print("Domain bulunamadı.")
        return

    # Kategorileri çek (Ana İstek)
    # Smali kodunda "Ana Istek" olarak domainin kendisine istek atılıyor
    raw_cat = make_inat_request(domain, "")
    decrypted_cat = decrypt_response(raw_cat)
    
    if not decrypted_cat:
        print("Kategoriler alınamadı.")
        return

    categories = json.loads(decrypted_cat)
    
    m3u_content = "#EXTM3U\n"
    
    print(f"Bulunan Kategori Sayısı: {len(categories)}")

    for cat in categories:
        cat_name = cat.get('catName', 'Unknown')
        cat_url = cat.get('catUrl', '')
        
        # Boş URL veya "Hata Bildir" gibi gereksiz kategorileri atla
        if not cat_url or "Hata" in cat_name or "Destek" in cat_name:
            continue
            
        print(f"İşleniyor: {cat_name}")
        
        # Kategori içeriğini çek
        raw_channels = make_inat_request(domain, cat_url)
        decrypted_channels = decrypt_response(raw_channels)
        
        if not decrypted_channels:
            continue
            
        try:
            channels = json.loads(decrypted_channels)
            
            for ch in channels:
                ch_name = ch.get('chName', ch.get('diziName', 'Bilinmeyen Kanal'))
                ch_url = ch.get('chUrl', ch.get('diziUrl', ''))
                ch_img = ch.get('chImg', ch.get('diziImg', ''))
                ch_type = ch.get('chType', ch.get('diziType', ''))

                # Sadece doğrudan oynatılabilir veya canlı yayın linklerini almayı dene
                # Smali kodunda 'live_url' ve 'web' tipleri genellikle doğrudan linktir.
                # Diziler ve filmler genellikle ikinci bir istek (parseMovieResponse) gerektirir, 
                # bu yüzden statik m3u'da oynatılamazlar, onları atlıyoruz veya raw URL koyuyoruz.
                
                final_url = ch_url
                
                # Basit bir düzenleme: Eğer URL http ile başlamıyorsa domaini ekle
                if final_url and not final_url.startswith("http"):
                     # Bazı durumlarda göreceli link olabilir, genellikle tam link gelir ama kontrol edelim
                     pass 

                if final_url:
                    m3u_content += f'#EXTINF:-1 tvg-logo="{ch_img}" group-title="{cat_name}",{ch_name}\n'
                    # Referer gerektiren yayınlar için header ekleme (VLC desteklemez ama bazı IPTV playerlar #EXTVLCOPT ile destekler)
                    m3u_content += f'#EXTVLCOPT:http-user-agent={USER_AGENT}\n'
                    m3u_content += f'#EXTVLCOPT:http-referrer={REFERER}\n'
                    m3u_content += f"{final_url}\n"

        except json.JSONDecodeError:
            continue

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(m3u_content)
    print(f"{OUTPUT_FILE} oluşturuldu.")

if __name__ == "__main__":
    generate_m3u()
