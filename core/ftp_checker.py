import socket
from ftplib import FTP, error_perm, error_temp


class FTPChecker:



    def __init__(self, ip, port=21, timeout=5):
        self.ip = ip
        self.port = port
        self.timeout = timeout

    def banner(self):
        """FTP banner'ını al."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.ip, self.port))
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return "REFUSED"
        except Exception as e:
            return f"ERROR: {e}"

    def anonymous_login(self):
        """Anonymous FTP girişi dene."""
        try:
            ftp = FTP(timeout=self.timeout)
            ftp.connect(self.ip, self.port)
            ftp.login("anonymous", "anonymous")
            return {"success": True, "ftp": ftp}
        except error_perm as e:
            return {"success": False, "error": f"Permission denied: {e}"}
        except error_temp as e:
            return {"success": False, "error": f"Temp error: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_files(self, ftp, path="/"):
        """Dizin içeriğini listele."""
        try:
            ftp.cwd(path)
            files = []
            ftp.retrlines("LIST", files.append)
            return files
        except Exception:
            return []

    def check_write(self, ftp, path="/"):
        """Yazma izni kontrolü."""
        try:
            ftp.cwd(path)
            test_file = "redstrike_test.txt"
            ftp.storbinary(f"STOR {test_file}", b"test")
            try:
                ftp.delete(test_file)
                return {"writable": True, "deleted": True}
            except Exception:
                return {"writable": True, "deleted": False}
        except error_perm:
            return {"writable": False, "deleted": False}
        except Exception:
            return {"writable": False, "deleted": False}