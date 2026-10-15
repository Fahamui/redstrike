
import os
import fnmatch


class ScopeManager:
    """
    Scope (kapsam) yöneticisi.
    
    Kullanım:
        sm = ScopeManager()
        sm.enabled = True
        sm.load_from_file("scope.txt")
        sm.is_in_scope("api.hedef.com")  # True/False
    """

    def __init__(self):
        self.in_scope = []          # ["*.hedef.com", "api.hedef.com"]
        self.out_of_scope = []      # ["admin.hedef.com"]
        self.enabled = True
        self.scope_file = None

    # ============================================================
    # AÇ / KAPAT
    # ============================================================
    def enable(self):
        self.enabled = True
        return True

    def disable(self):
        self.enabled = False
        return False

    def toggle(self):
        self.enabled = not self.enabled
        return self.enabled

    # ============================================================
    # DOSYADAN YÜKLE
    # ============================================================
    def load_from_file(self, path):
        if not os.path.exists(path):
            return False

        self.in_scope = []
        self.out_of_scope = []
        self.scope_file = path

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("!"):
                        self.out_of_scope.append(line[1:].strip().lower())
                    else:
                        self.in_scope.append(line.lower())
            return True
        except Exception:
            return False

    # ============================================================
    # KONTROL
    # ============================================================
    def is_in_scope(self, target):
        if not self.enabled:
            return True

        host = target.lower().strip()
        host = host.replace("https://", "").replace("http://", "")
        host = host.split("/")[0].split(":")[0]

        for pattern in self.out_of_scope:
            if fnmatch.fnmatch(host, pattern):
                return False

        if not self.in_scope:
            return True

        for pattern in self.in_scope:
            if fnmatch.fnmatch(host, pattern):
                return True

        return False

    # ============================================================
    # BİLGİ
    # ============================================================
    def get_scope_summary(self):
        return {
            "enabled": self.enabled,
            "in_scope": self.in_scope,
            "out_of_scope": self.out_of_scope,
            "scope_file": self.scope_file,
        }

    def clear(self):
        self.in_scope = []
        self.out_of_scope = []
        self.scope_file = None