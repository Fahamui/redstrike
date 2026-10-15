import socket


class BannerGrabber:

    def __init__(self, ip, timeout=3):
        self.ip = ip
        self.timeout = timeout

    def grab(self, port):
        """Bir porttan banner al."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.ip, port))

            # HTTP/HTTPS için özel istek
            if port in (80, 8080):
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + self.ip.encode() + b"\r\n\r\n")
            elif port in (443, 8443):
                # SSL portu — banner grab için ssl wrap
                import ssl
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=self.ip)
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + self.ip.encode() + b"\r\n\r\n")

            banner = s.recv(2048).decode("utf-8", errors="ignore").strip()
            s.close()

            # İlk satırı al
            first_line = banner.split("\n")[0].strip()

            # Server header'ı çıkar (HTTP için)
            server = None
            for line in banner.split("\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break

            return {
                "port": port,
                "banner": first_line,
                "server": server,
                "full": banner[:200],
            }
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception:
            return None

    def grab_all(self, ports):
        """Birden fazla porttan banner al."""
        results = []
        for port in ports:
            r = self.grab(port)
            if r:
                results.append(r)
        return results

    def detect_service(self, banner, port):
        """Banner'dan servis tespit et."""
        banner_lower = banner.lower()

        # Bilinen servisler
        if "ssh" in banner_lower:
            return "SSH"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower:
            return "SMTP"
        elif "pop3" in banner_lower:
            return "POP3"
        elif "imap" in banner_lower:
            return "IMAP"
        elif "http" in banner_lower:
            return "HTTP"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "redis" in banner_lower:
            return "Redis"
        elif "mongo" in banner_lower:
            return "MongoDB"

        # Port bazlı
        port_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        }
        return port_map.get(port, "Bilinmiyor")