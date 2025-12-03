from seleniumbase import SB
import re
import sys

# --- AYARLAR ---
ATV_LIVE_URL = "https://www.atv.com.tr/canli-yayin"
OUTPUT_FILE = "playlist.m3u"
ATV_LOGO_URL = "https://upload.wikimedia.org/wikipedia/commons/thumb/1/17/Atv_logo_2022.svg/1200px-Atv_logo_2022.svg.png"

def get_stream_url_with_browser():
    """
    SeleniumBase UC modu ile Cloudflare'i geçer ve m3u8 linkini çeker.
    Bu yöntem, gerçek bir tarayıcıyı simüle eder.
    """
    print("[-] Tarayıcı (SeleniumBase UC) başlatılıyor...")
    
    # sb (SeleniumBase) context manager ile tarayıcıyı aç ve otomatik kapat
    # uc=True: Undetected Chrome modu (Cloudflare için kritik)
    # headless=False: Xvfb kullandığımız için arayüz varmış gibi çalışır.
    with SB(uc=True, headless=False, page_load_strategy="eager") as sb:
        try:
            print(f"[-] {ATV_LIVE_URL} adresine gidiliyor...")
            
            # uc_open_with_reconnect: Cloudflare engeline takılırsa tekrar dener
            sb.uc_open_with_reconnect(ATV_LIVE_URL, reconnect_time=5)
            
            # Eğer Cloudflare hala captcha gösteriyorsa, tıklamayı dene
            if "Just a moment" in sb.get_title():
                print("[-] Cloudflare algılandı, bypass deneniyor...")
                try:
                    sb.uc_gui_click_captcha()
                except Exception as e:
                    print(f"[UYARI] Captcha tıklanamadı, devam ediliyor. Hata: {e}")
                
                # Sayfanın yüklenmesi için bekle
                print("[-] Sayfanın tam yüklenmesi bekleniyor...")
                sb.wait_for_element("video", timeout=30) # Video elementi gelene kadar bekle

            print("[OK] Sayfa yüklendi. Kaynak kodu analiz ediliyor...")
            
            # Sayfanın tam HTML içeriğini al
            html_content = sb.get_page_source()
            
            # Regex ile m3u8 linkini bul
            # Desen: src: 'https://...m3u8...'
            match = re.search(r"src:\s*['\"]([^'\"]+\.m3u8[^'\"]*)['\"]", html_content)
            
            if match:
                stream_url = match.group(1)
                print(f"[OK] Canlı yayın linki bulundu.")
                return stream_url
            else:
                print("[HATA] Sayfa kaynağında m3u8 linki bulunamadı.")
                return None

        except Exception as e:
            print(f"[FATAL] Tarayıcı hatası: {e}")
            # Hata durumunda ekran görüntüsü al (Debug için)
            # sb.save_screenshot("hata_ekrani.png")
            return None

def generate_m3u(stream_url):
    m3u_content = f"""#EXTM3U
#EXTINF:-1 tvg-id="ATV.tr" tvg-logo="{ATV_LOGO_URL}",ATV HD
#EXTVLCOPT:http-user-agent=Mozilla/5.0
{stream_url}
"""
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(m3u_content)
        print(f"[BAŞARILI] {OUTPUT_FILE} güncellendi.")
    except Exception as e:
        print(f"[FATAL] Dosya yazma hatası: {e}")

if __name__ == "__main__":
    print("--- ATV Canlı Yayın Çekici ---")
    
    url = get_stream_url_with_browser()
    
    if url:
        generate_m3u(url)
    else:
        print("[!] İşlem başarısız oldu.")
        sys.exit(1)
