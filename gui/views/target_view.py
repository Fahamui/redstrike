import webbrowser
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QProgressBar, QLabel, QFrame, QMenu, QApplication
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from core.engine import RedStrikeEngine
from core.scope_manager import ScopeManager


class TargetView(QWidget):
    def __init__(self):
        super().__init__()
        self.engine = None
        self.console = None
        self.shared_logger = None
        self.scope = ScopeManager()
        self.init_ui()

    def set_console(self, console_widget):
        self.console = console_widget

    def set_shared_logger(self, logger_func):
        self.shared_logger = logger_func

    def log(self, message):
        if self.shared_logger:
            self.shared_logger(message)
        elif self.console:
            self.console.append(message)

    # ============================================================
    # ARAYÜZ
    # ============================================================
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        # --- HEDEF SATIRI ---
        target_row = QHBoxLayout()

        lbl = QLabel("Hedef:")
        lbl.setStyleSheet("color: #ff2b2b; font-weight: bold;")
        target_row.addWidget(lbl)

        self.txt_target = QLineEdit()
        self.txt_target.setPlaceholderText("https://ornek.com  veya  192.168.1.1")
        self.txt_target.setStyleSheet("""
            QLineEdit {
                background-color: #1a0000;
                color: #fff;
                border: 1px solid #4d0000;
                border-radius: 4px;
                padding: 6px;
                font-family: Consolas, monospace;
            }
            QLineEdit:focus { border: 1px solid #ff2b2b; }
        """)
        target_row.addWidget(self.txt_target, 1)

        self.btn_start = QPushButton("Taramayı Başlat")
        self.btn_start.setStyleSheet("""
            QPushButton {
                background-color: #4d0000;
                color: #fff;
                border: 1px solid #ff2b2b;
                border-radius: 4px;
                padding: 6px 16px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #660000; }
            QPushButton:disabled { background-color: #2a2a2a; color: #666; }
        """)
        self.btn_start.clicked.connect(self.start_scan)
        target_row.addWidget(self.btn_start)

        self.btn_stop = QPushButton("İptal Et")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                background-color: #1a1a1a;
                color: #ff2b2b;
                border: 1px solid #ff2b2b;
                border-radius: 4px;
                padding: 6px 16px;
            }
            QPushButton:hover { background-color: #2a0000; }
            QPushButton:disabled { color: #555; border: 1px solid #333; }
        """)
        self.btn_stop.clicked.connect(self.stop_scan)
        target_row.addWidget(self.btn_stop)

        layout.addLayout(target_row)

        # --- SCOPE BÖLÜMÜ ---
        scope_frame = QFrame()
        scope_frame.setStyleSheet("""
            QFrame {
                background-color: #0d0d0d;
                border: 1px solid #2a0000;
                border-radius: 6px;
            }
        """)
        scope_layout = QVBoxLayout(scope_frame)
        scope_layout.setContentsMargins(12, 8, 12, 8)
        scope_layout.setSpacing(6)

        row1 = QHBoxLayout()

        self.cb_scope = QCheckBox("Scope Kontrolü Aktif")
        self.cb_scope.setChecked(True)
        self.cb_scope.setStyleSheet("""
            QCheckBox { color: #ff2b2b; font-weight: bold; font-size: 12px; }
            QCheckBox::indicator {
                width: 14px; height: 14px;
                border: 1px solid #4d0000;
                border-radius: 3px;
                background: #1a0000;
            }
            QCheckBox::indicator:checked { background: #ff2b2b; }
        """)
        self.cb_scope.toggled.connect(self.on_scope_toggle)
        row1.addWidget(self.cb_scope)

        self.txt_scope_file = QLineEdit("scope.txt")
        self.txt_scope_file.setPlaceholderText("scope.txt")
        self.txt_scope_file.setStyleSheet("""
            QLineEdit {
                background-color: #1a0000;
                color: #fff;
                border: 1px solid #4d0000;
                border-radius: 4px;
                padding: 4px;
                font-family: Consolas, monospace;
                font-size: 12px;
            }
        """)
        row1.addWidget(self.txt_scope_file, 1)

        self.btn_load_scope = QPushButton("Yükle")
        self.btn_load_scope.setStyleSheet("""
            QPushButton {
                background-color: #4d0000;
                color: #fff;
                border: 1px solid #ff2b2b;
                border-radius: 4px;
                padding: 4px 12px;
                font-size: 12px;
            }
            QPushButton:hover { background-color: #660000; }
        """)
        self.btn_load_scope.clicked.connect(self.load_scope)
        row1.addWidget(self.btn_load_scope)

        scope_layout.addLayout(row1)

        self.lbl_scope = QLabel("Scope yüklenmedi")
        self.lbl_scope.setStyleSheet("color: #888; font-size: 11px;")
        scope_layout.addWidget(self.lbl_scope)

        layout.addWidget(scope_frame)

        # --- MODÜL SEÇİMİ ---
        module_frame = QFrame()
        module_frame.setStyleSheet("""
            QFrame {
                background-color: #0d0d0d;
                border: 1px solid #2a0000;
                border-radius: 6px;
            }
        """)
        module_layout = QHBoxLayout(module_frame)
        module_layout.setContentsMargins(12, 8, 12, 8)

        lbl_mod = QLabel("Modüller:")
        lbl_mod.setStyleSheet("color: #888; font-size: 11px; font-weight: bold;")
        module_layout.addWidget(lbl_mod)

        # Checkbox tanımları
        self.cb_recon     = QCheckBox("Recon")
        self.cb_port      = QCheckBox("Port")
        self.cb_endpoint  = QCheckBox("Dizin")
        self.cb_web       = QCheckBox("Web Vuln")
        self.cb_subdomain = QCheckBox("Subdomain")
        self.cb_ssl       = QCheckBox("SSL/TLS")
        self.cb_banner    = QCheckBox("Banner")
        self.cb_ftp       = QCheckBox("FTP")
        self.cb_ratelimit = QCheckBox("Rate Limit")

        cb_style = """
            QCheckBox { color: #ccc; font-size: 12px; padding: 3px; }
            QCheckBox::indicator {
                width: 14px; height: 14px;
                border: 1px solid #4d0000;
                border-radius: 3px;
                background: #1a0000;
            }
            QCheckBox::indicator:checked { background: #ff2b2b; }
        """

        # Tüm checkbox'ları ekle (Rate Limit hariç)
        for cb in [self.cb_recon, self.cb_port, self.cb_endpoint,
                   self.cb_web, self.cb_subdomain, self.cb_ssl,
                   self.cb_banner, self.cb_ftp]:
            cb.setStyleSheet(cb_style)
            module_layout.addWidget(cb)

        # Rate Limit (checkbox + input yan yana)
        self.cb_ratelimit.setStyleSheet(cb_style)
        module_layout.addWidget(self.cb_ratelimit)

        self.txt_rate_limit = QLineEdit("10")
        self.txt_rate_limit.setFixedWidth(40)
        self.txt_rate_limit.setStyleSheet("""
            QLineEdit {
                background-color: #1a0000;
                color: #fff;
                border: 1px solid #4d0000;
                border-radius: 3px;
                padding: 2px 4px;
                font-family: Consolas, monospace;
                font-size: 11px;
            }
        """)
        module_layout.addWidget(self.txt_rate_limit)

        lbl_rate_sn = QLabel("istek/sn")
        lbl_rate_sn.setStyleSheet("color: #888; font-size: 10px;")
        module_layout.addWidget(lbl_rate_sn)

        module_layout.addStretch()

        # Varsayılan seçimler
        self.cb_recon.setChecked(True)
        self.cb_port.setChecked(True)
        self.cb_endpoint.setChecked(True)

        layout.addWidget(module_frame)

        # --- İLERLEME ÇUBUĞU ---
        progress_frame = QFrame()
        progress_frame.setStyleSheet("""
            QFrame {
                background-color: #0d0d0d;
                border: 1px solid #2a0000;
                border-radius: 6px;
            }
        """)
        progress_layout = QVBoxLayout(progress_frame)
        progress_layout.setContentsMargins(12, 8, 12, 8)
        progress_layout.setSpacing(4)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: #1a0000;
                border: 1px solid #4d0000;
                border-radius: 4px;
                text-align: center;
                color: #fff;
                height: 18px;
                font-size: 11px;
            }
            QProgressBar::chunk {
                background-color: #ff2b2b;
                border-radius: 3px;
            }
        """)
        progress_layout.addWidget(self.progress)

        self.lbl_progress = QLabel("Hazır")
        self.lbl_progress.setStyleSheet("color: #888; font-size: 11px;")
        progress_layout.addWidget(self.lbl_progress)

        layout.addWidget(progress_frame)

        # --- SONUÇ TABLOSU ---
        results_lbl = QLabel("Tarama ve Keşif Sonuçları:")
        results_lbl.setStyleSheet("color: #ff2b2b; font-weight: bold; font-size: 13px;")
        layout.addWidget(results_lbl)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Modül", "Bulgu / Detay", "Durum"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.doubleClicked.connect(self.copy_cell_to_clipboard)
        self.table.setToolTip("Hücreye çift tıkla → kopyala | Sağ tık → menü")

        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #0d0d0d;
                color: #ddd;
                border: 1px solid #2a0000;
                border-radius: 6px;
                gridline-color: transparent;
            }
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid #1a1a1a;
            }
            QTableWidget::item:selected {
                background-color: #1e0000;
            }
            QHeaderView::section {
                background-color: #1a0000;
                color: #ff2b2b;
                border: none;
                border-bottom: 1px solid #4d0000;
                padding: 8px 6px;
                font-weight: bold;
                font-size: 11px;
                letter-spacing: 1px;
            }
        """)
        layout.addWidget(self.table)

    # ============================================================
    # TARAMA KONTROL
    # ============================================================
    def start_scan(self):
        # Eski engine'i temizle
        if self.engine:
            try:
                if self.engine.isRunning():
                    self.engine.stop()
                    self.engine.wait(2000)
            except Exception:
                pass
            self.engine = None

        target = self.txt_target.text().strip()
        if not target:
            self.log("[!] Hedef girilmedi.")
            return

        from urllib.parse import urlparse
        parsed = urlparse(target)
        if not parsed.scheme:
            parsed = urlparse("http://" + target)
        hostname = parsed.netloc or parsed.path.split("/")[0]

        if self.scope and self.scope.enabled and not self.scope.is_in_scope(target):
            self.log(f"[!] HEDEF SCOPE DIŞI: {target}")
            self.log("[!] Tarama başlatılmadı.")
            return

        selected = []
        if self.cb_recon.isChecked():     selected.append("recon")
        if self.cb_port.isChecked():      selected.append("port")
        if self.cb_endpoint.isChecked():  selected.append("endpoint")
        if self.cb_web.isChecked():       selected.append("web")
        if self.cb_subdomain.isChecked(): selected.append("subdomain")
        if self.cb_ssl.isChecked():       selected.append("ssl")
        if self.cb_banner.isChecked():    selected.append("banner")
        if self.cb_ftp.isChecked():       selected.append("ftp")
        if self.cb_ratelimit.isChecked(): selected.append("ratelimit")

        if not selected:
            self.log("[!] Hiç modül seçilmedi.")
            return

        try:
            rate = int(self.txt_rate_limit.text().strip())
        except ValueError:
            rate = 10

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.lbl_progress.setText("Başlatılıyor...")

        self.engine = RedStrikeEngine(
            target,
            modules=selected,
            scope_manager=self.scope,
            rate_limit=rate
        )
        self.engine.new_result.connect(self.on_result)
        self.engine.new_log.connect(self.log)
        self.engine.progress_update.connect(self.on_progress)
        self.engine.finished_scan.connect(self.on_finished)
        self.engine.start()

    def stop_scan(self):
        if self.engine:
            self.engine.stop()
            self.log("[!] Durdurma isteği gönderildi...")

    # ============================================================
    # SİNYAL YAKALAYICILAR
    # ============================================================
    def on_result(self, data):
        row = self.table.rowCount()
        self.table.insertRow(row)

        module = data.get("module", "?")
        detail = data.get("detail", "")
        status = data.get("status", "")

        item_module = QTableWidgetItem(module)
        item_detail = QTableWidgetItem(detail)
        item_status = QTableWidgetItem(status)

        module_colors = {
            "Recon": "#4aa3ff",
            "Port Scanner": "#ff8800",
            "Endpoint": "#4ade80",
            "Web Vuln": "#ff3b3b",
            "Subdomain": "#c084fc",
            "SSL/TLS": "#22d3ee",
            "IP Intel": "#facc15",
            "Banner": "#fb923c",
            "FTP": "#38bdf8",
            "Rate Limit": "#a3e635",
            "Info Leak": "#f87171",
            "Scope": "#ef4444",
        }
        item_module.setForeground(QColor(module_colors.get(module, "#ccc")))

        if "KRİTİK" in status or "SÜRESİ" in status or "ZAYIF" in status or "ACİL" in status:
            item_status.setForeground(QColor("#ff0000"))
        elif "YÜKSEK" in status:
            item_status.setForeground(QColor("#ff6600"))
        elif "Kritik" in status:
            item_status.setForeground(QColor("#ff3b3b"))
        elif "Bulundu" in status or "Aktif" in status or "Güvenli" in status:
            item_status.setForeground(QColor("#4ade80"))
        elif "Bilgi" in status or "Çözümlendi" in status:
            item_status.setForeground(QColor("#4aa3ff"))
        elif "Uyarı" in status or "Yasaklı" in status or "Yönlendirme" in status:
            item_status.setForeground(QColor("#ff8800"))
        elif "CDN Arkası" in status:
            item_status.setForeground(QColor("#facc15"))
        elif "Bulunamadı" in status or "Pasif" in status or "Atlandı" in status:
            item_status.setForeground(QColor("#888"))
        elif "ZAFİYET" in status:
            item_status.setForeground(QColor("#ff0000"))

        item_module.setToolTip(f"Çift tıkla → kopyala: {module}")
        item_detail.setToolTip(f"Çift tıkla → kopyala: {detail}")
        item_status.setToolTip(f"Çift tıkla → kopyala: {status}")

        for item in (item_module, item_detail, item_status):
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)

        self.table.setItem(row, 0, item_module)
        self.table.setItem(row, 1, item_detail)
        self.table.setItem(row, 2, item_status)

        self.table.scrollToBottom()

    def on_progress(self, value, message):
        self.progress.setValue(value)
        self.lbl_progress.setText(message)

    def on_finished(self):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_progress.setText("Tamamlandı")

    # ============================================================
    # KOPYALAMA
    # ============================================================
    def copy_cell_to_clipboard(self, index):
        text = index.data()
        if text:
            QApplication.clipboard().setText(str(text))
            short = str(text)[:80] + ("..." if len(str(text)) > 80 else "")
            self.log(f"[*] Kopyalandı: {short}")

    # ============================================================
    # SAĞ TIK MENÜSÜ
    # ============================================================
    def show_context_menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return

        text = str(index.data())
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #1a1a1a;
                color: #ddd;
                border: 1px solid #4d0000;
                padding: 4px;
            }
            QMenu::item {
                padding: 6px 20px;
                border-radius: 3px;
            }
            QMenu::item:selected {
                background-color: #4d0000;
                color: #fff;
            }
        """)

        act_copy = menu.addAction("📋  Kopyala")
        act_open = menu.addAction("🔗  URL'yi Aç")
        act_target = menu.addAction("🎯  Hedef Yap")

        action = menu.exec(self.table.viewport().mapToGlobal(pos))

        if action == act_copy:
            QApplication.clipboard().setText(text)
            self.log(f"[*] Kopyalandı: {text}")

        elif action == act_open:
            if "http" in text:
                url = text.split(" (")[0].strip()
                webbrowser.open(url)
                self.log(f"[*] Tarayıcıda açılıyor: {url}")
            else:
                self.log("[!] Bu hücrede URL yok.")

        elif action == act_target:
            target = None
            if "Domain:" in text:
                target = text.split("Domain:")[1].split("|")[0].strip()
            elif "http" in text:
                target = text.split(" (")[0].strip()
            elif text.count(".") >= 1 and " " not in text:
                target = text.strip()

            if target:
                self.txt_target.setText(target)
                self.log(f"[*] Hedef olarak ayarlandı: {target}")
            else:
                self.log("[!] Bu hücreden hedef çıkarılamadı.")

    # ============================================================
    # SCOPE
    # ============================================================
    def on_scope_toggle(self, checked):
        if not checked:
            from PySide6.QtWidgets import QMessageBox
            reply = QMessageBox.warning(
                self,
                "⚠️ Scope Kontrolü Kapatılıyor",
                "Scope kontrolünü kapatmak üzeresiniz.\n\n"
                "Bu durumda:\n"
                "• Scope dışı hedefler de taranabilir\n"
                "• Bug bounty kurallarını ihlal edebilirsiniz\n"
                "• Yasal risk oluşabilir\n\n"
                "Sadece kendi lab'ınızda çalışıyorsanız kapatın.\n\n"
                "Devam etmek istiyor musunuz?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply != QMessageBox.Yes:
                self.cb_scope.blockSignals(True)
                self.cb_scope.setChecked(True)
                self.cb_scope.blockSignals(False)
                return

        if self.scope:
            if checked:
                self.scope.enable()
                self.log("[*] Scope kontrolü AÇIK")
            else:
                self.scope.disable()
                self.log("[!] Scope kontrolü KAPALI — dikkatli kullan!")

    def load_scope(self):
        path = self.txt_scope_file.text().strip()
        if self.scope.load_from_file(path):
            s = self.scope.get_scope_summary()
            self.log(f"[+] Scope yüklendi: {path}")
            self.log(f"    In scope: {len(s['in_scope'])} | Out of scope: {len(s['out_of_scope'])}")
            self.update_scope_label()
        else:
            self.log(f"[!] Scope dosyası bulunamadı: {path}")

    def update_scope_label(self):
        if not self.scope:
            return
        s = self.scope.get_scope_summary()
        status = "AÇIK" if s["enabled"] else "KAPALI"
        text = f"Scope: {status} | ✅ {len(s['in_scope'])} izinli | ❌ {len(s['out_of_scope'])} yasak"
        if s["scope_file"]:
            text += f" | Dosya: {s['scope_file']}"
        self.lbl_scope.setText(text)