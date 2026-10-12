import requests
import socket
from urllib.parse import urlparse, urljoin
from PySide6.QtCore import QThread, Signal
import concurrent.futures
import urllib3
import os

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RedStrikeEngine(QThread):
    new_result = Signal(dict)
    new_log = Signal(str)
    finished_scan = Signal()

    def __init__(self, target_url, custom_wordlist_path=None):
        super().__init__()
        clean_url = target_url.strip()
        parsed = urlparse(clean_url)
        if not parsed.scheme:
            clean_url = "http://" + clean_url
            parsed = urlparse(clean_url)
            
        self.netloc = parsed.netloc
        self.base_url = f"{parsed.scheme}://{parsed.netloc}/"
        self.is_cancelled = False
        self.custom_wordlist_path = custom_wordlist_path
        self.wordlist = []

    def run(self):
        if self.is_cancelled:
            return

        self.new_log.emit(f"[+] Hedef analiz ve keşif başlatıldı: {self.base_url}")
        
        # 1. Adım: İstihbarat, IP ve Port Analizi
        recon_data = self.perform_reconnaissance()

        if self.is_cancelled:
            self.finished_scan.emit()
            return

        # 2. Adım: Sade Wordlist Hazırlama ve Kaydetme (Tabloya basılmaz, sadece loglanır)
        self.build_and_save_wordlist(recon_data)

        # 3. Adım: Endpoint Tarama Döngüsü
        try:
            for path in self.wordlist:
                if self.is_cancelled:
                    break
                
                current_url = urljoin(self.base_url, path)
                self.scan_single_path(current_url)
                
        except Exception as e:
            self.new_log.emit(f"[X] Motor Kritik Hata: {str(e)}")
        finally:
            if self.is_cancelled:
                self.new_log.emit("[!] Tarama kullanıcı tarafından durduruldu.")
            else:
                self.new_log.emit("[+] Tarama tamamlandı.")
            
            self.finished_scan.emit()

    def perform_reconnaissance(self):
        recon = {"ip": "", "server": "", "registrar": ""}
        self.new_log.emit(f"[*] Hedef istihbarat bilgileri toplanıyor...")
        
        # Temel IP Çözümleme
        ip_address = None
        try:
            ip_address = socket.gethostbyname(self.netloc)
            recon["ip"] = ip_address
            self.new_result.emit({
                "module": "Recon / Hedef",
                "detail": f"Hedef Domain: {self.netloc} | IP: {ip_address}",
                "status": "Çözümlendi"
            })
            self.new_log.emit(f"[+] Hedef IP: {ip_address}")
        except Exception:
            pass

        # Port Taraması
        if ip_address:
            self.scan_target_ports(ip_address)

        # Sunucu Bilgisi
        try:
            resp = requests.head(self.base_url, timeout=3.0, verify=False, allow_redirects=True)
            server = resp.headers.get("Server", "Gizlenmiş / Bilinmiyor")
            recon["server"] = server
            self.new_result.emit({
                "module": "Recon / Web Servis",
                "detail": f"Sunucu Yazılımı: {server}",
                "status": "Header Bilgisi"
            })
            self.new_log.emit(f"[+] Sunucu Yazılımı: {server}")
        except Exception:
            pass

        # Whois Bilgisi
        if HAS_WHOIS:
            try:
                w = whois.whois(self.netloc)
                reg_name = w.get("registrar", "Bilinmiyor")
                creation_date = w.get("creation_date", "Bilinmiyor")
                if isinstance(creation_date, list):
                    creation_date = str(creation_date[0])
                recon["registrar"] = str(reg_name)
                
                self.new_result.emit({
                    "module": "Recon / Whois",
                    "detail": f"Kayıtçi (Registrar): {reg_name} | Tarih: {creation_date}",
                    "status": "Whois Bilgisi"
                })
                self.new_log.emit(f"[+] Whois - Kayıt: {reg_name}")
            except Exception:
                pass
        
        return recon

    def scan_target_ports(self, ip_address):
        target_ports = [21, 80, 110, 143, 443, 465, 587, 993, 995]
        self.new_log.emit(f"[*] Port taraması başlatılıyor ({len(target_ports)} port)...")
        open_ports = []

        for port in target_ports:
            if self.is_cancelled:
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.6)
                result = sock.connect_ex((ip_address, port))
                sock.close()

                if result == 0:
                    service_name = self.get_service_name(port)
                    open_ports.append(f"{port} ({service_name})")
                    self.new_log.emit(f"[+] PORT AÇIK: {ip_address}:{port} ({service_name})")
            except Exception:
                pass

        if open_ports:
            ports_str = ", ".join(open_ports)
            self.new_result.emit({
                "module": "Port Scanner",
                "detail": f"Açık Portlar: [{ports_str}]",
                "status": f"{len(open_ports)} Port Aktif"
            })
        else:
            self.new_result.emit({
                "module": "Port Scanner",
                "detail": "Belirtilen portların tümü kapalı veya filtrelenmiş.",
                "status": "Port Bulunamadı"
            })

    def get_service_name(self, port):
        services = {
            21: "FTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 465: "SMTPS", 587: "Submission",
            993: "IMAPS", 995: "POP3S"
        }
        return services.get(port, "Servis")

    def build_and_save_wordlist(self, recon):
        words = [
            "robots.txt",
            "sitemap.xml",
            "admin",
            "admin.php",
            "login",
            "login.php",
            "dashboard",
            "panel",
            "api/v1",
            "config.json",
            ".env",
            "backup",
            "db.sql",
            "test",
            "index.php"
        ]

        if self.custom_wordlist_path:
            try:
                with open(self.custom_wordlist_path, "r", encoding="utf-8") as f:
                    for line in f:
                        clean = line.strip()
                        if clean and not clean.startswith("#") and clean not in words:
                            words.append(clean)
            except Exception:
                pass

        self.wordlist = words
        
        try:
            dir_path = "wordlists"
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
                
            output_filename = f"wordlist_{self.netloc.replace('.', '_')}.txt"
            output_path = os.path.join(dir_path, output_filename)
            
            with open(output_path, "w", encoding="utf-8") as f:
                for word in sorted(self.wordlist):
                    f.write(word + "\n")
            
            # Tabloya satır eklemek yerine sadece terminale log atıyoruz:
            self.new_log.emit(f"[+] {len(self.wordlist)} adetlik sade liste 'wordlists/' klasörüne kaydedildi: {output_path}")
        except Exception as e:
            self.new_log.emit(f"[X] Kayıt hatası: {str(e)}")

    def scan_single_path(self, current_url):
        if self.is_cancelled:
            return
            
        headers = {"User-Agent": "RedStrike-Suite/1.0 (Security Scanner)"}
        
        def do_request():
            return requests.get(
                current_url, 
                headers=headers, 
                timeout=2.0, 
                verify=False, 
                allow_redirects=True
            )

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(do_request)
                response = future.result(timeout=2.5)
            
            if self.is_cancelled:
                return
                
            status_code = response.status_code
            
            if status_code == 200:
                status_text = "Açık / Bulundu (200)"
                self.new_log.emit(f"[+] BULUNDU (200): {current_url}")
            elif status_code == 403:
                status_text = "Yasaklı (403)"
            elif status_code == 404:
                status_text = "Bulunamadı (404)"
            else:
                status_text = f"Durum Kodu: {status_code}"

            result = {
                "module": "Endpoint Enum",
                "detail": f"{current_url} (Yanıt: {status_code})",
                "status": status_text
            }
            self.new_result.emit(result)
            
        except Exception:
            pass

    def stop(self):
        self.is_cancelled = True