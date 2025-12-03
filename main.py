import re
from curl_cffi import requests
import sys

# --- AYARLAR ---
ATV_LIVE_URL = "https://www.atv.com.tr/canli-yayin"
OUTPUT_FILE = "playlist.m3u"
ATV_LOGO_URL = "https://upload.wikimedia.org/wikipedia/commons/thumb/1/17/Atv_logo_2022.svg/1200px-Atv_logo_2022.svg.png"

def get_atv_stream_url():
    """
    ATV'nin canlı yayın sayfasından .m3u8 linkini çeker.
    Cloudflare'ı aşmak için curl_cffi kullanır.
    """
    print("[-] ATV canlı yayın sayfası taranıyor...")
    
    # Gerçek bir tarayıcıyı taklit eden bir oturum başlat
    session = requests.Session(impersonate="chrome120")
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Referer": "https://www.atv.com.tr/"
    })

    try:
        # Sayfaya istek at
        response = session.get(ATV_LIVE_URL, timeout=20)
        
        # İstek başarısız olursa veya Cloudflare takılırsa hata ver
        if response.status_code != 200:
            print(f"[HATA] Sayfaya erişilemedi. Durum Kodu: {response.status_code}")
            return None

        html_content = response.text
        
        # Eklentinin kullandığı mantıkla aynı: Sayfa kaynağında 'src: "....m3u8..."' ara
        # Regex Deseni: 'src:' ile başlayan, tek tırnak içinde .m3u8 içeren her şeyi bul
        match = re.search(r"src:\s*'([^']+\.m3u8[^']*)'", html_content)
        
        if match:
            stream_url = match.group(1)
            print(f"[OK] Canlı yayın linki bulundu: {stream_url[:50]}...")
            return stream_url
        else:
            print("[HATA] Sayfa kaynağında m3u8 linki bulunamadı. Site yapısı değişmiş olabilir.")
            # Debug için sayfa kaynağının bir kısmını yazdırabiliriz
            # print(html_content[:1000])
            return None

    except Exception as e:
        print(f"[FATAL] Tarama sırasında bir hata oluştu: {e}")
        return None

def generate_m3u_file(stream_url):
    """Bulunan link ile M3U dosyasını oluşturur."""
    
    # M3U formatı
    m3u_content = f"""#EXTM3U
#EXTINF:-1 tvg-id="ATV.tr" tvg-logo="{ATV_LOGO_URL}",ATV HD
#EXTVLCOPT:http-user-agent=Mozilla/5.0
{stream_url}
"""
    
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(m3u_content)
        print(f"[BAŞARILI] {OUTPUT_FILE} dosyası oluşturuldu/güncellendi.")
    except Exception as e:
        print(f"[FATAL] Dosya yazma hatası: {e}")

if __name__ == "__main__":
    print("--- ATV M3U Oluşturucu Başlatıldı ---")
    
    url = get_atv_stream_url()
    
    if url:
        generate_m3u_file(url)
    else:
        print("[!] İşlem başarısız oldu. Çıkılıyor.")
        # Hata durumunda workflow'un başarısız olması için exit code 1 ile çık
        sys.exit(1)
