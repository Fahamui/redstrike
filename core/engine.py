import requests
import socket
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from PySide6.QtCore import QThread, Signal
import concurrent.futures
import urllib3
import os

from core.rate_limiter import RateLimiter
from core.rate_limit_tester import RateLimitTester
from core.banner_grabber import BannerGrabber
from core.ftp_checker import FTPChecker

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tüm HTTP istekleri için tek timeout (saniye)
REQUEST_TIMEOUT = 5

CLOUDFLARE_RANGES = [
    "172.64.", "172.65.", "172.66.", "172.67.",
    "172.68.", "172.69.", "172.70.", "172.71.",
    "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.",
    "173.245.48.", "103.21.244.", "103.22.200.",
    "103.31.4.", "141.101.64.", "108.162.192.",
    "190.93.240.", "188.114.96.", "197.234.240.",
    "198.41.128.", "162.158.", "131.0.72.",
]


class RedStrikeEngine(QThread):
    new_result = Signal(dict)
    new_log = Signal(str)
    progress_update = Signal(int, str)
    finished_scan = Signal()

    def __init__(self, target_url, modules=None, custom_wordlist_path=None, scope_manager=None,rate_limit=10):
        super().__init__()
        clean_url = target_url.strip()
        parsed = urlparse(clean_url)
        if not parsed.scheme:
            clean_url = "http://" + clean_url
            parsed = urlparse(clean_url)

        self.netloc = parsed.netloc
        self.base_url = clean_url if clean_url.endswith("/") else clean_url
        self.is_cancelled = False
        self.custom_wordlist_path = custom_wordlist_path
        self.wordlist = []
        self.modules = modules or ["recon", "port", "endpoint"]
        self.scope = scope_manager
        self.rate_limiter = RateLimiter(max_per_second=rate_limit)
        

    # ============================================================
    # ANA ÇALIŞTIRICI
    # ============================================================
    def run(self):
        try:
            if self.is_cancelled:
                return
            
            if self.scope:
                if self.scope.enabled and not self.scope.is_in_scope(self.netloc):
                    self.new_log.emit(f"[!] HEDEF SCOPE DIŞI: {self.netloc}")
                    self.new_result.emit({
                        "module": "Scope",
                        "detail": f"Hedef scope dışı: {self.netloc}",
                        "status": "ENGELLENDİ"
                    })
                    self.finished_scan.emit()
                    return
                elif self.scope.enabled:
                    self.new_log.emit(f"[+] Scope kontrolü: {self.netloc} izinli")
                else:
                    self.new_log.emit("[!] Scope kontrolü KAPALI — dikkatli kullan!")

            self.new_log.emit(f"[+] Tarama başlatıldı: {self.base_url}")
            self.new_log.emit(f"[*] Aktif modüller: {', '.join(self.modules)}")
            
            self.new_log.emit(f"[+] Tarama başlatıldı: {self.base_url}")
            self.new_log.emit(f"[*] Aktif modüller: {', '.join(self.modules)}")

            total = len(self.modules)
            step = 0

            if "recon" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "Recon / İstihbarat toplanıyor...")
                try:
                    self.perform_reconnaissance()
                except Exception as e:
                    self.new_log.emit(f"[X] Recon hatası: {e}")

            if "port" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "Port taraması yapılıyor...")
                try:
                    ip = socket.gethostbyname(self.netloc)
                    self.scan_target_ports(ip)
                except Exception as e:
                    self.new_log.emit(f"[X] Port hatası: {e}")

            if "endpoint" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "Dizin / endpoint taranıyor...")
                try:
                    self.build_and_save_wordlist({})
                    for path in self.wordlist:
                        if self.is_cancelled:
                            break
                        current_url = urljoin(self.base_url, path)
                        self.scan_single_path(current_url)
                except Exception as e:
                    self.new_log.emit(f"[X] Endpoint hatası: {e}")

            if "web" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "Web zafiyet taraması...")
                try:
                    self.scan_web_vulnerabilities()
                except Exception as e:
                    self.new_log.emit(f"[X] Web Vuln hatası: {e}")

            if "subdomain" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "Alt alan adı keşfi...")
                try:
                    self.enumerate_subdomains()
                except Exception as e:
                    self.new_log.emit(f"[X] Subdomain hatası: {e}")

            if "ssl" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "SSL/TLS analizi...")
                try:
                    self.analyze_ssl()
                except Exception as e:
                    self.new_log.emit(f"[X] SSL hatası: {e}")
            
            if "ratelimit" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "Rate limit testi...")
                try:
                    self.test_rate_limit()
                except Exception as e:
                    self.new_log.emit(f"[X] Rate limit testi hatası: {e}")

            if "banner" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "Banner grab...")
                try:
                    ip = socket.gethostbyname(self.netloc)
                    self.grab_banners(ip)
                except Exception as e:
                    self.new_log.emit(f"[X] Banner hatası: {e}")

            if "ftp" in self.modules and not self.is_cancelled:
                step += 1
                self.progress_update.emit(int(step / total * 100), "FTP kontrolü...")
                try:
                    ip = socket.gethostbyname(self.netloc)
                    self.check_ftp(ip)
                except Exception as e:
                    self.new_log.emit(f"[X] FTP hatası: {e}")

            if self.is_cancelled:
                self.new_log.emit("[!] Tarama kullanıcı tarafından durduruldu.")
            else:
                self.progress_update.emit(100, "Tamamlandı")
                self.new_log.emit("[+] Tarama tamamlandı.")

        except Exception as e:
            self.new_log.emit(f"[X] KRİTİK HATA: {e}")
            self.progress_update.emit(100, "Hata ile bitti")

        finally:
            self.finished_scan.emit()

    # ============================================================
    # MODÜL 1: RECON
    # ============================================================
    def perform_reconnaissance(self):
        recon = {"ip": "", "server": "", "registrar": ""}
        self.new_log.emit("[*] Hedef istihbarat bilgileri toplanıyor...")

        try:
            ip = socket.gethostbyname(self.netloc)
            recon["ip"] = ip
            self.new_result.emit({
                "module": "Recon",
                "detail": f"Domain: {self.netloc} | IP: {ip}",
                "status": "Bilgi"
            })
            self.new_log.emit(f"[+] Hedef IP: {ip}")
        except Exception:
            pass

        try:
            resp = requests.head(self.base_url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
            server = resp.headers.get("Server", "Gizli / Bilinmiyor")
            recon["server"] = server
            self.new_result.emit({
                "module": "Recon",
                "detail": f"Server: {server}",
                "status": "Bilgi"
            })
            self.new_log.emit(f"[+] Server: {server}")
        except Exception:
            pass

        if HAS_WHOIS:
            try:
                w = whois.whois(self.netloc)
                reg = w.get("registrar", "Bilinmiyor")
                cdate = w.get("creation_date", "Bilinmiyor")
                if isinstance(cdate, list):
                    cdate = str(cdate[0])
                recon["registrar"] = str(reg)
                self.new_result.emit({
                    "module": "Recon",
                    "detail": f"Registrar: {reg} | Tarih: {cdate}",
                    "status": "Bilgi"
                })
                self.new_log.emit(f"[+] Whois: {reg}")
            except Exception:
                pass

        return recon

    # ============================================================
    # MODÜL 2: PORT TARAMA
    # ============================================================
    def scan_target_ports(self, ip_address):
        target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                        3306, 3389, 5432, 5900, 6379, 8080, 8443]
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
                    service = self.get_service_name(port)
                    open_ports.append(f"{port} ({service})")
                    self.new_log.emit(f"[+] PORT AÇIK: {ip_address}:{port} ({service})")
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
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        return services.get(port, "Servis")

    # ============================================================
    # MODÜL 3: ENDPOINT / DİZİN
    # ============================================================
    def build_and_save_wordlist(self, recon):
        words = [
            "robots.txt", "sitemap.xml", "sitemap_index.xml",
            "humans.txt", "security.txt", ".well-known/security.txt",
            "favicon.ico", "crossdomain.xml", "clientaccesspolicy.xml",
            "readme.md", "README.md", "readme.txt", "README.txt",
            "changelog.txt", "CHANGELOG.md", "license.txt", "LICENSE",
            "manifest.json", "browserconfig.xml", "ads.txt", "app-ads.txt",

            "admin", "admin.php", "admin.html", "admin.aspx", "admin.jsp",
            "admin/", "admin/login", "admin/dashboard", "admin/index",
            "admin/login.php", "admin/login.html", "admin/index.php",
            "admin_area", "adminarea", "admin1", "admin2", "admin3",
            "administrator", "administrator.php", "administrator/",
            "administrator/index.php", "administrator/login.php",
            "adminpanel", "admin-panel", "admin_panel", "admin-panel.php",
            "adm", "adm/", "adm.php",
            "admincp", "admincp/", "admin_cp",
            "moderator", "mod/", "moderator/",
            "sysadmin", "sys-admin", "sysadmin/",
            "webadmin", "web-admin", "webadmin/",
            "siteadmin", "site-admin", "siteadmin/",
            "superadmin", "super-admin", "superadmin/",

            "panel", "panel.php", "panel/", "panel.html",
            "cp", "cp/", "cpanel", "cpanel/", "cpanel.php",
            "manage", "manage/", "management", "management/", "manager",
            "backend", "backend/", "back-end", "back-end/", "backoffice",
            "control", "control/", "controlpanel", "control-panel",
            "dashboard", "dashboard/", "dashboard.php",
            "yonetim", "yonetim/", "yönetim", "yönetim/",
            "giris", "giris/", "giriş", "giriş/",

            "login", "login.php", "login.html", "login.aspx", "login.jsp",
            "login/", "signin", "sign-in", "sign_in",
            "signup", "sign-up", "register", "registration",
            "auth", "auth/", "authenticate", "authentication",
            "logout", "log-out", "logout.php",
            "password", "password.php", "forgot-password", "reset-password",
            "account", "account/", "accounts", "accounts/",
            "user", "user/", "users", "users/", "user.php", "users.php",
            "profile", "profile/", "profile.php",
            "session", "session/", "sessions",

            "wp-admin", "wp-admin/", "wp-login.php", "wp-login",
            "wp-content", "wp-content/", "wp-includes", "wp-includes/",
            "wp-config.php", "wp-config.php.bak", "wp-config.php~",
            "wp-json", "wp-json/", "wp-json/wp/v2/users",
            "xmlrpc.php", "wp-cron.php", "wp-signup.php",
            "wp-admin/admin-ajax.php", "wp-admin/install.php",

            "config", "config/", "config.php", "config.json",
            "config.yml", "config.yaml", "config.xml", "config.ini",
            "configuration.php", "configuration/",
            "settings", "settings/", "settings.php", "settings.json",
            "database", "database/", "database.php", "database.yml",
            "db", "db/", "db.php", "db.sql", "db.sqlite", "db.sqlite3",
            "sql", "sql/", "dump.sql", "backup.sql", "database.sql",
            ".env", ".env.local", ".env.production", ".env.backup",
            ".env.example", ".env.dev", ".env.test",
            "credentials", "credentials.json", "credentials.yml",
            "secrets", "secrets.json", "secrets.yml",
            "phpinfo.php", "info.php", "test.php", "phpinfo",

            "backup", "backup/", "backups", "backups/",
            "backup.zip", "backup.tar.gz", "backup.sql",
            "backup.rar", "backup.7z",
            "site.zip", "site.tar.gz", "website.zip",
            "www.zip", "web.zip", "public_html.zip",
            "old", "old/", "old.zip", "old.tar.gz",
            "archive", "archive/", "archives",
            "2024.zip", "2025.zip", "2026.zip",

            ".git", ".git/", ".git/config", ".git/HEAD",
            ".gitignore", ".gitattributes", ".gitmodules",
            ".svn", ".svn/", ".svn/entries",
            ".hg", ".hg/", ".hgignore",
            ".bzr", ".bzr/",
            ".DS_Store", "Thumbs.db",

            "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/",
            "api/v3", "api/v3/", "api/docs", "api/swagger",
            "api/swagger.json", "api/openapi.json", "api/graphql",
            "graphql", "graphql/", "graphiql",
            "rest", "rest/", "rest/api", "rest/v1",
            "soap", "soap/", "wsdl", "wsdl/",
            "swagger", "swagger/", "swagger.json", "swagger.yaml",
            "openapi.json", "openapi.yaml",
            "endpoints", "endpoints/",

            "private", "private/", "secret", "secret/",
            "hidden", "hidden/", "internal", "internal/",
            "confidential", "confidential/",
            "keys", "keys/", "key", "key/",
            "passwords", "passwords.txt", "passwd",
            "htpasswd", ".htpasswd",
            "id_rsa", "id_rsa.pub", "id_dsa",
            "ssh", "ssh/", ".ssh/", ".ssh/id_rsa",

            "test", "test/", "tests", "tests/", "testing", "testing/",
            "demo", "demo/", "demos", "demos/",
            "dev", "dev/", "development", "development/",
            "staging", "staging/", "stage", "stage/",
            "beta", "beta/", "alpha", "alpha/",
            "prod", "prod/", "production", "production/",
            "temp", "temp/", "tmp", "tmp/",
            "cache", "cache/", "cached", "cached/",
            "logs", "logs/", "log", "log/", "log.txt",
            "error", "error/", "errors", "errors/", "error.log",
            "debug", "debug/", "debug.log",
            "install", "install/", "installer", "installer/",
            "setup", "setup/", "update", "update/", "upgrade",
            "maintenance", "maintenance/",

            "wp-admin", "wp-content", "wp-includes",
            "administrator", "components", "modules", "plugins",
            "templates", "themes", "includes", "uploads",
            "media", "media/", "images", "images/", "img", "img/",
            "css", "css/", "js", "js/", "fonts", "fonts/",
            "assets", "assets/", "static", "static/",
            "public", "public/", "dist", "dist/", "build", "build/",

            "upload", "upload/", "uploads", "uploads/",
            "file", "file/", "files", "files/",
            "download", "download/", "downloads", "downloads/",
            "document", "document/", "documents", "documents/",
            "doc", "doc/", "docs", "docs/", "documentation",
            "pdf", "pdf/", "attachments", "attachments/",

            "blog", "blog/", "blogs", "blogs/",
            "forum", "forum/", "forums", "forums/",
            "community", "community/", "discussions",
            "news", "news/", "articles", "articles/",
            "post", "post/", "posts", "posts/",
            "comment", "comment/", "comments", "comments/",
            "feed", "feed/", "rss", "rss/", "atom", "atom/",

            "shop", "shop/", "store", "store/", "cart", "cart/",
            "checkout", "checkout/", "payment", "payment/",
            "order", "order/", "orders", "orders/",
            "product", "product/", "products", "products/",
            "category", "category/", "categories", "categories/",

            "administracion", "administracion/",
            "administration", "administration/",
            "verwaltung", "verwaltung/",
            "amministrazione", "amministrazione/",
            "administracao", "administracao/",

            "server-status", "server-info", "status", "status/",
            "health", "health/", "healthcheck", "health-check",
            "ping", "ping/", "version", "version/",
            "metrics", "metrics/", "stats", "stats/",
            "monitor", "monitor/", "monitoring", "monitoring/",

            "shell.php", "shell", "cmd.php", "cmd",
            "webshell.php", "webshell", "c99.php", "r57.php",
            "backdoor.php", "backdoor",
            "uploader.php", "upload.php", "filemanager",
            "filemanager.php", "elfinder", "elfinder.php",
            "tiny_mce", "tinymce", "fckeditor", "ckeditor",

            "index", "index.php", "index.html", "index.htm",
            "index.aspx", "index.jsp", "index.cgi",
            "home", "home/", "home.php", "home.html",
            "main", "main/", "main.php",
            "default", "default/", "default.php",
            "404", "404.php", "404.html",
            "500", "500.php", "500.html",
            "phpmyadmin", "phpMyAdmin", "pma", "pma/",
            "mysql", "mysql/", "mariadb", "mariadb/",
            "adminer", "adminer.php", "adminer/",
            "webmail", "webmail/", "mail", "mail/",
            "cgi-bin", "cgi-bin/", "cgi", "cgi/",
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
            self.new_log.emit(f"[+] {len(self.wordlist)} kelimelik liste kaydedildi: {output_path}")
        except Exception as e:
            self.new_log.emit(f"[X] Kayıt hatası: {str(e)}")

    def scan_single_path(self, current_url):
        if self.is_cancelled:
            return
        self.rate_limiter.wait()

        headers = {"User-Agent": "RedStrike-Suite/1.0 (Security Scanner)"}

        try:
            response = requests.get(
                current_url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True
            )

            if self.is_cancelled:
                return

            status_code = response.status_code
            body = response.text.lower()

            php_signs = [
                "fatal error",
                "parse error",
                "stack trace",
                "call to undefined function",
                "call to a member function",
                "undefined variable",
                "undefined index",
                "warning:",
                "notice:",
                "deprecated:",
                "on line",
                "in /hermes/",
                "in /var/www/",
                "in /home/",
                "in /public_html/",
                "in /usr/share/",
                "in /var/log/",
                "in c:\\",
                "thrown in",
                "mysql_connect",
                "mysql_query",
                "mysqli_",
                "pg_connect",
                "failed opening required",
                "include_path=",
                "headers already sent",
                "cannot modify header information",
            ]

            for sign in php_signs:
                if sign in body:
                    self.new_result.emit({
                        "module": "Info Leak",
                        "detail": f"Bilgi sızıntısı (PHP hata): {current_url}",
                        "status": "KRİTİK"
                    })
                    self.new_log.emit(f"[!] BİLGİ SIZINTISI: {current_url}")
                    self.new_log.emit(f"[!] İmza: '{sign}'")
                    break

            if status_code == 200:
                status_text = "Bulundu (200)"
                self.new_log.emit(f"[+] BULUNDU (200): {current_url}")

            elif status_code == 201:
                status_text = "Oluşturuldu (201)"

            elif status_code == 204:
                status_text = "İçerik Yok (204)"

            elif status_code == 301:
                status_text = "Kalıcı Yönlendirme (301)"

            elif status_code == 302:
                status_text = "Geçici Yönlendirme (302)"

            elif status_code == 307:
                status_text = "Yönlendirme (307)"

            elif status_code == 308:
                status_text = "Kalıcı Yönlendirme (308)"

            elif status_code == 401:
                status_text = "Kimlik Doğrulama (401)"

            elif status_code == 403:
                status_text = "Yasaklı (403)"

            elif status_code == 405:
                status_text = "Metod İzinli Değil (405)"

            elif status_code == 404:
                # 404'leri gösterme (gürültü olmasın)
                return

            elif status_code == 409:
                status_text = "Çakışma (409) — Var ama erişim kısıtlı"

            elif status_code == 429:
                status_text = "Rate Limit (429) — Çok fazla istek"

            elif status_code == 500:
                leak_signs = [
                    "stack trace", "fatal error", "on line",
                    "/hermes/", "/var/www/", "/home/", "/public_html/",
                    "mysql_connect", "mysql_query", "pg_connect",
                    "call to undefined function", "call to a member function",
                ]
                has_leak = any(sign in body for sign in leak_signs)

                if has_leak:
                    status_text = "KRİTİK: 500 + Bilgi Sızıntısı"
                    self.new_log.emit(f"[!] KRİTİK 500 SIZINTI: {current_url}")
                else:
                    status_text = "500 Internal Server Error (generic)"
                    self.new_log.emit(f"[!] 500 HATASI (generic): {current_url}")

            elif status_code == 502:
                status_text = "502 Bad Gateway"

            elif status_code == 503:
                status_text = "503 Service Unavailable"

            elif status_code == 504:
                status_text = "504 Gateway Timeout"

            elif 300 <= status_code < 400:
                status_text = f"Yönlendirme ({status_code})"

            else:
                status_text = f"Durum: {status_code}"

            # ============================================================
            # SONUCU RAPORLA
            # ============================================================
            self.new_result.emit({
                "module": "Endpoint",
                "detail": f"{current_url} (Yanıt: {status_code})",
                "status": status_text
            })

        except requests.exceptions.Timeout:
            self.new_log.emit(f"[!] TIMEOUT: {current_url}")
        except requests.exceptions.ConnectionError:
            self.new_log.emit(f"[!] BAĞLANTI HATASI: {current_url}")
        except requests.exceptions.SSLError:
            self.new_log.emit(f"[!] SSL HATASI: {current_url}")
        except requests.exceptions.TooManyRedirects:
            self.new_log.emit(f"[!] ÇOK FAZLA YÖNLENDİRME: {current_url}")
        except Exception as e:
            self.new_log.emit(f"[!] HATA ({current_url}): {e}")

    # ============================================================
    # MODÜL 4: WEB VULN — DEBUG'LI
    # ============================================================
    def _build_url(self, base_url, param, value):
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def scan_web_vulnerabilities(self):
        self.new_log.emit("[*] Web zafiyet taraması başlatılıyor...")

        base_url = self.base_url
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        if not params:
            self.new_log.emit("[!] URL'de parametre yok. Yaygın parametreler deneniyor...")
            common_params = ["id", "page", "q", "file"]
            for p in common_params:
                if self.is_cancelled:
                    return
                self.new_log.emit(f"[*] Test parametresi: {p}")
                self.test_parameter_sqli(base_url, p, "1")
                self.test_parameter_xss(base_url, p, "1")
            return

        for i, (param_name, values) in enumerate(params.items()):
            if self.is_cancelled:
                return
            if i >= 3:
                break
            value = values[0] if values else "1"
            self.new_log.emit(f"[*] Parametre test ediliyor: {param_name} = {value}")
            self.test_parameter_sqli(base_url, param_name, value)
            self.test_parameter_xss(base_url, param_name, value)
            self.test_parameter_lfi(base_url, param_name, value)

    def test_parameter_sqli(self, base_url, param, original_value):
        self.new_log.emit(f"[*] SQLi testleri başlıyor: {param}={original_value}")

        payloads = [
            f"{original_value}'",
            f"{original_value}%27",
            f"{original_value}\"",
            f"{original_value}' OR '1'='1",
        ]
        sql_errors = [
            "sql syntax", "mysql_fetch", "mysqli_", "ora-", "postgresql",
            "sqlite", "microsoft ole db", "odbc sql server", "syntax error",
            "unclosed quotation mark", "warning: mysql", "valid mysql result",
            "you have an error in your sql", "mysql_num_rows",
            "supplied argument is not a valid mysql",
        ]
        
        php_errors = [
            "fatal error", "parse error", "warning:", "notice:",
            "call to undefined function", "undefined variable",
            "stack trace:", "thrown in", "on line",
            "mysql_connect", "mysql_query", "mysql_fetch",
            "cannot modify header information",
            "headers already sent",
            "include(", "require(", "include_once(",
            "failed opening required",
        ]

        for payload in payloads:
            if self.is_cancelled:
                return
            self.rate_limiter.wait()
            url = self._build_url(base_url, param, payload)
            self.new_log.emit(f"[*] Deneniyor: {url}")
            try:
                r = requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT,
                    verify=False,
                    allow_redirects=True
                )
                self.new_log.emit(f"[*] → HTTP {r.status_code} | Boyut: {len(r.text)}")
                body = r.text.lower()
                for err in sql_errors:
                    if err in body:
                        self.new_result.emit({
                            "module": "Web Vuln",
                            "detail": f"SQLi tespit edildi: {param}={payload} ({err})",
                            "status": "KRİTİK"
                        })
                        self.new_log.emit(f"[!] SQLi BULUNDU: {url}")
                        return
                self.new_log.emit("[*] → Zafiyet izi yok")
            except requests.exceptions.Timeout:
                self.new_log.emit(f"[!] TIMEOUT: {url}")
            except requests.exceptions.ConnectionError:
                self.new_log.emit(f"[!] BAĞLANTI HATASI: {url}")
            except Exception as e:
                self.new_log.emit(f"[!] HATA: {e}")

    def test_parameter_xss(self, base_url, param, original_value):
        self.new_log.emit(f"[*] XSS testi: {param}")
        payload = "rStRk<svg/onload=alert(1)>"
        url = self._build_url(base_url, param, payload)
        self.new_log.emit(f"[*] Deneniyor: {url}")
        try:
            r = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
            self.new_log.emit(f"[*] → HTTP {r.status_code} | Boyut: {len(r.text)}")
            if payload in r.text:
                self.new_result.emit({
                    "module": "Web Vuln",
                    "detail": f"XSS (yansıma) tespit edildi: {param}",
                    "status": "YÜKSEK"
                })
                self.new_log.emit(f"[!] XSS BULUNDU: {url}")
            else:
                self.new_log.emit("[*] → XSS yok")
        except requests.exceptions.Timeout:
            self.new_log.emit(f"[!] XSS TIMEOUT: {url}")
        except Exception as e:
            self.new_log.emit(f"[!] XSS HATA: {e}")

    def test_parameter_lfi(self, base_url, param, original_value):
        self.new_log.emit(f"[*] LFI testi: {param}")
        payloads = [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
        ]
        lfi_signatures = [
            "root:x:0:0", "root:*:0:0", "daemon:x:", "[boot loader]",
            "[extensions]", "for 16-bit app support",
        ]
        for payload in payloads:
            if self.is_cancelled:
                return
            url = self._build_url(base_url, param, payload)
            self.new_log.emit(f"[*] Deneniyor: {url}")
            try:
                r = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
                self.new_log.emit(f"[*] → HTTP {r.status_code} | Boyut: {len(r.text)}")
                for sig in lfi_signatures:
                    if sig in r.text:
                        self.new_result.emit({
                            "module": "Web Vuln",
                            "detail": f"LFI tespit edildi: {param}={payload}",
                            "status": "KRİTİK"
                        })
                        self.new_log.emit(f"[!] LFI BULUNDU: {url}")
                        return
                self.new_log.emit("[*] → LFI yok")
            except requests.exceptions.Timeout:
                self.new_log.emit(f"[!] LFI TIMEOUT: {url}")
            except Exception as e:
                self.new_log.emit(f"[!] LFI HATA: {e}")

    # ============================================================
    # MODÜL 5: SUBDOMAIN
    # ============================================================
    def is_cloudflare(self, ip):
        return any(ip.startswith(r) for r in CLOUDFLARE_RANGES)

    def detect_wildcard(self, base_domain):
        import random
        import string
        for _ in range(2):
            random_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=15))
            test_domain = f"{random_sub}.{base_domain}"
            try:
                ip = socket.gethostbyname(test_domain)
                return ip
            except socket.gaierror:
                continue
            except Exception:
                continue
        return None

    def enumerate_subdomains(self):
        self.new_log.emit("[*] Alt alan adı keşfi başlatılıyor...")

        base_domain = self.netloc
        if ":" in base_domain:
            base_domain = base_domain.split(":")[0]

        wildcard_ip = self.detect_wildcard(base_domain)
        if wildcard_ip:
            self.new_log.emit(f"[!] UYARI: Wildcard DNS tespit edildi! (*.{base_domain} → {wildcard_ip})")
            self.new_result.emit({
                "module": "Subdomain",
                "detail": f"Wildcard DNS var: *.{base_domain} → {wildcard_ip}",
                "status": "Uyarı"
            })
            self.new_result.emit({
                "module": "Subdomain",
                "detail": "Tüm sonuçlar aynı IP'ye çözümlenebilir. Dikkatli yorumlayın.",
                "status": "Uyarı"
            })
        else:
            self.new_log.emit("[*] Wildcard DNS yok, sonuçlar güvenilir.")

        common_subs = [
            "www", "mail", "webmail", "smtp", "pop", "imap",
            "api", "api-v1", "api-v2", "rest", "graphql",
            "dev", "staging", "test", "beta", "demo", "sandbox",
            "admin", "panel", "dashboard", "manage", "cpanel",
            "blog", "shop", "store", "news", "forum",
            "cdn", "static", "assets", "media", "img",
            "vpn", "remote", "gateway", "proxy",
            "ftp", "sftp", "files", "upload",
            "git", "gitlab", "jenkins", "ci", "cd",
            "db", "mysql", "postgres", "redis", "mongo",
            "ns1", "ns2", "dns", "mx",
            "support", "help", "docs", "wiki",
        ]

        if self.custom_wordlist_path:
            try:
                with open(self.custom_wordlist_path, "r", encoding="utf-8") as f:
                    for line in f:
                        clean = line.strip()
                        if clean and not clean.startswith("#"):
                            sub = clean.split(".")[0]
                            if sub not in common_subs:
                                common_subs.append(sub)
            except Exception:
                pass

        self.new_log.emit(f"[*] {len(common_subs)} alt alan adı deneniyor...")

        found = []

        def check_subdomain(sub):
            if self.is_cancelled:
                return None
            full = f"{sub}.{base_domain}"
            try:
                ip = socket.gethostbyname(full)
                return (sub, full, ip)
            except socket.gaierror:
                return None
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, s): s for s in common_subs}
            for future in concurrent.futures.as_completed(futures):
                if self.is_cancelled:
                    break
                result = future.result()
                if result:
                    found.append(result)

        if not found:
            self.new_result.emit({
                "module": "Subdomain",
                "detail": "Hiç alt alan adı bulunamadı.",
                "status": "Bulunamadı"
            })
            return

        real_found = []
        wildcard_found = []

        for sub, full, ip in sorted(found):
            if wildcard_ip and ip == wildcard_ip:
                wildcard_found.append((sub, full, ip))
            else:
                real_found.append((sub, full, ip))

        if real_found:
            self.new_log.emit(f"[+] {len(real_found)} GERÇEK alt alan adı bulundu.")
            for sub, full, ip in real_found:
                if self.is_cloudflare(ip):
                    self.new_result.emit({
                        "module": "Subdomain",
                        "detail": f"{full} → {ip} [CLOUDFLARE CDN]",
                        "status": "CDN Arkası"
                    })
                else:
                    self.new_result.emit({
                        "module": "Subdomain",
                        "detail": f"{full} → {ip}",
                        "status": "Bulundu"
                    })
                self.report_ip_intel(ip)

        if wildcard_found:
            self.new_log.emit(f"[!] {len(wildcard_found)} wildcard şüphelisi filtrelendi.")
            for sub, full, ip in wildcard_found[:3]:
                self.new_result.emit({
                    "module": "Subdomain",
                    "detail": f"{full} → {ip} [WILDCARD ŞÜPHELİSİ]",
                    "status": "Filtrelendi"
                })
            if len(wildcard_found) > 3:
                self.new_result.emit({
                    "module": "Subdomain",
                    "detail": f"... ve {len(wildcard_found) - 3} tane daha wildcard şüphelisi",
                    "status": "Filtrelendi"
                })

        self.new_result.emit({
            "module": "Subdomain",
            "detail": f"Gerçek: {len(real_found)} | Wildcard şüphelisi: {len(wildcard_found)}",
            "status": f"{len(real_found)} Gerçek"
        })

    def report_ip_intel(self, ip):
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                return
            data = r.json()
            org = data.get("org", "Bilinmiyor")
            country = data.get("country", "?")
            city = data.get("city", "?")
            hostname = data.get("hostname", "")

            detail = f"IP: {ip} | {org} | {country}"
            if city and city != "?":
                detail += f" / {city}"
            if hostname:
                detail += f" | {hostname}"

            self.new_result.emit({
                "module": "IP Intel",
                "detail": detail,
                "status": "Bilgi"
            })
            self.new_log.emit(f"[*] IP Intel: {org} - {country}")
        except Exception:
            pass

    # ============================================================
    # MODÜL 6: SSL/TLS
    # ============================================================
    def analyze_ssl(self):
        import ssl
        from datetime import datetime, timezone

        self.new_log.emit("[*] SSL/TLS analizi başlatılıyor...")

        parsed = urlparse(self.base_url)
        hostname = parsed.hostname
        port = parsed.port or 443

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    tls_version = ssock.version()

            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())

                subject = x509_cert.subject
                cn_attrs = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                org_attrs = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                common_name = cn_attrs[0].value if cn_attrs else "Bilinmiyor"
                org = org_attrs[0].value if org_attrs else "Bilinmiyor"

                issuer = x509_cert.issuer
                issuer_cn_attrs = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                issuer_org_attrs = issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                issuer_cn = issuer_cn_attrs[0].value if issuer_cn_attrs else "Bilinmiyor"
                issuer_org = issuer_org_attrs[0].value if issuer_org_attrs else "Bilinmiyor"

                not_before = x509_cert.not_valid_before_utc
                not_after = x509_cert.not_valid_after_utc
                days_left = (not_after - datetime.now(timezone.utc)).days

                san_list = []
                try:
                    san_ext = x509_cert.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    )
                    san_list = san_ext.value.get_values_for_type(x509.DNSName)
                except Exception:
                    pass

            except ImportError:
                self.new_log.emit("[!] cryptography yok. pip install cryptography")
                common_name = "Bilinmiyor"
                org = ""
                issuer_cn = "Bilinmiyor"
                issuer_org = ""
                not_before = None
                not_after = None
                days_left = None
                san_list = []

            self.new_result.emit({
                "module": "SSL/TLS",
                "detail": f"Sertifika Sahibi: {common_name}" + (f" ({org})" if org and org != "Bilinmiyor" else ""),
                "status": "Bilgi"
            })
            self.new_result.emit({
                "module": "SSL/TLS",
                "detail": f"Düzenleyen (CA): {issuer_org} - {issuer_cn}",
                "status": "Bilgi"
            })
            self.new_result.emit({
                "module": "SSL/TLS",
                "detail": f"TLS Versiyonu: {tls_version} | Cipher: {cipher[0]}",
                "status": "Bilgi"
            })

            if days_left is not None and not_after:
                if days_left < 0:
                    status = f"SÜRESİ DOLMUŞ ({abs(days_left)} gün önce)"
                elif days_left < 30:
                    status = f"{days_left} gün kaldı (Yakında doluyor)"
                else:
                    status = f"{days_left} gün geçerli"

                self.new_result.emit({
                    "module": "SSL/TLS",
                    "detail": f"Geçerlilik: {not_before.strftime('%Y-%m-%d')} → {not_after.strftime('%Y-%m-%d')}",
                    "status": status
                })

            if san_list:
                san_str = ", ".join(san_list[:5])
                if len(san_list) > 5:
                    san_str += f" ... (+{len(san_list) - 5} tane daha)"
                self.new_result.emit({
                    "module": "SSL/TLS",
                    "detail": f"SAN: {san_str}",
                    "status": "Bilgi"
                })

            if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                self.new_result.emit({
                    "module": "SSL/TLS",
                    "detail": f"ZAYIF PROTOKOL: {tls_version}",
                    "status": "Kritik"
                })
            elif tls_version == "TLSv1.2":
                self.new_result.emit({
                    "module": "SSL/TLS",
                    "detail": "TLS 1.2 — kabul edilebilir, TLS 1.3 önerilir.",
                    "status": "Uyarı"
                })
            elif tls_version == "TLSv1.3":
                self.new_result.emit({
                    "module": "SSL/TLS",
                    "detail": "TLS 1.3 — güncel ve güvenli.",
                    "status": "Güvenli"
                })

            weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
            cipher_name = cipher[0]
            if any(w in cipher_name.upper() for w in weak_ciphers):
                self.new_result.emit({
                    "module": "SSL/TLS",
                    "detail": f"ZAYIF CIPHER: {cipher_name}",
                    "status": "Kritik"
                })
            else:
                self.new_result.emit({
                    "module": "SSL/TLS",
                    "detail": f"Cipher güçlü: {cipher_name} ({cipher[2]} bit)",
                    "status": "Güvenli"
                })

        except Exception as e:
            self.new_result.emit({
                "module": "SSL/TLS",
                "detail": f"SSL hatası: {e}",
                "status": "Hata"
            })

    # ============================================================
    # rate limit
    # ============================================================
    def test_rate_limit(self):
        self.new_log.emit("[*] Rate limit testi başlatılıyor...")

        # Test edilecek endpoint'ler
        endpoints = [
            self.base_url,
            urljoin(self.base_url, "api"),
            urljoin(self.base_url, "api/v1"),
            urljoin(self.base_url, "login"),
            urljoin(self.base_url, "api/login"),
        ]

        for endpoint in endpoints:
            if self.is_cancelled:
                return
            try:
                tester = RateLimitTester(endpoint, max_requests=50,is_cancelled=lambda: self.is_cancelled)
                result = tester.test()


                if result.get("cancelled"):
                    self.new_log.emit("[!] Rate limit testi iptal edildi.")
                    return

                if result["vulnerable"]:
                    self.new_result.emit({
                        "module": "Rate Limit",
                        "detail": f"Rate limit YOK: {endpoint} ({result['success']} istek başarılı)",
                        "status": "ZAFİYET"
                    })
                    self.new_log.emit(f"[!] RATE LIMIT YOK: {endpoint}")
                elif result["rate_limit_exists"]:
                    self.new_result.emit({
                        "module": "Rate Limit",
                        "detail": f"Rate limit VAR: {endpoint} ({result['blocked_at']}. istekte engellendi)",
                        "status": "Korumalı"
                    })
                    self.new_log.emit(f"[+] Rate limit var: {endpoint}")
                else:
                    self.new_result.emit({
                        "module": "Rate Limit",
                        "detail": f"Test tamamlandı: {endpoint} ({result['success']} istek)",
                        "status": "Bilinmiyor"
                    })
            except Exception as e:
                self.new_log.emit(f"[!] Rate limit testi hatası: {e}")


    # ============================================================
    # banner grabber
    # ============================================================
    def grab_banners(self, ip_address):
        """Açık portlardan banner al."""
        self.new_log.emit("[*] Banner grab başlatılıyor...")

        bg = BannerGrabber(ip_address)

        # Açık portlar
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5432, 5900, 6379, 8080, 8443]

        results = bg.grab_all(ports)

        if not results:
            self.new_result.emit({
                "module": "Banner",
                "detail": "Hiç banner alınamadı.",
                "status": "Bulunamadı"
            })
            return

        for r in results:
            port = r["port"]
            banner = r["banner"]
            server = r["server"]
            service = bg.detect_service(banner, port)

            detail = f"[{port}/{service}] {banner}"
            if server:
                detail += f" | Server: {server}"

            self.new_result.emit({
                "module": "Banner",
                "detail": detail,
                "status": "Bilgi"
            })
            self.new_log.emit(f"[+] {port}/{service}: {banner}")

    
    # ============================================================
    # ftb
    # ============================================================
    
    def check_ftp(self, ip_address):
        """FTP kontrolü."""
        self.new_log.emit("[*] FTP kontrolü yapılıyor...")

        fc = FTPChecker(ip_address)
        banner = fc.banner()

        if banner == "REFUSED":
            self.new_result.emit({
                "module": "FTP",
                "detail": "Port 21 kapalı.",
                "status": "Kapalı"
            })
            return

        if not banner or banner.startswith("ERROR"):
            self.new_result.emit({
                "module": "FTP",
                "detail": f"Banner alınamadı: {banner}",
                "status": "Hata"
            })
            return

        # Banner
        self.new_result.emit({
            "module": "FTP",
            "detail": f"Banner: {banner}",
            "status": "Bilgi"
        })
        self.new_log.emit(f"[+] FTP Banner: {banner}")

        # Anonymous login
        result = fc.anonymous_login()

        if result["success"]:
            self.new_result.emit({
                "module": "FTP",
                "detail": "ANONYMOUS FTP AÇIK! (KRİTİK)",
                "status": "KRİTİK"
            })
            self.new_log.emit(f"[!] ANONYMOUS FTP: {ip_address}")

            ftp = result["ftp"]
            files = fc.list_files(ftp)
            if files:
                files_str = ", ".join(files[:5])
                self.new_result.emit({
                    "module": "FTP",
                    "detail": f"Dosyalar: {files_str}",
                    "status": "Bilgi"
                })

            write = fc.check_write(ftp)
            if write["writable"]:
                self.new_result.emit({
                    "module": "FTP",
                    "detail": "YAZMA İZNİ VAR! (Çok kritik)",
                    "status": "KRİTİK"
                })

            ftp.quit()
        else:
            self.new_result.emit({
                "module": "FTP",
                "detail": f"Anonymous login kapalı (iyi): {result.get('error', '')}",
                "status": "Güvenli"
            })
            self.new_log.emit(f"[+] FTP anonymous kapalı")
    # ============================================================
    # DURDUR
    # ============================================================
    def stop(self):
        self.is_cancelled = True