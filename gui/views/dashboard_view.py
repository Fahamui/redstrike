from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QGridLayout
)
from PySide6.QtCore import Qt


class StatCard(QFrame):
    """Güncellenebilir istatistik kartı."""
    def __init__(self, title, value, color="#ff2b2b"):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #121212;
                border: 1px solid {color};
                border-radius: 6px;
                padding: 8px;
            }}
        """)
        v = QVBoxLayout(self)
        
        lbl_title = QLabel(title.upper())
        lbl_title.setStyleSheet(f"color: {color}; font-size: 11px; letter-spacing: 1px;")
        lbl_title.setAlignment(Qt.AlignCenter)
        
        self.lbl_value = QLabel(str(value))
        self.lbl_value.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        self.lbl_value.setAlignment(Qt.AlignCenter)
        
        v.addWidget(lbl_title)
        v.addWidget(self.lbl_value)

    def set_value(self, value):
        self.lbl_value.setText(str(value))


class DashboardView(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Başlık
        title = QLabel("Operasyon Paneli (Dashboard)")
        title.setStyleSheet("color: #ff2b2b; font-size: 20px; font-weight: bold;")
        layout.addWidget(title)

        # --- İstatistik Kartları ---
        cards_layout = QHBoxLayout()
        self.card_targets = StatCard("Aktif Hedefler", 0, "#ff2b2b")
        self.card_vulns = StatCard("Bulunan Zafiyetler", 0, "#ff8800")
        self.card_modules = StatCard("Çalışan Modüller", "Aktif", "#00aaff")
        self.card_critical = StatCard("Kritik Bulgular", 0, "#ff0000")

        for c in [self.card_targets, self.card_vulns, self.card_modules, self.card_critical]:
            cards_layout.addWidget(c)
        layout.addLayout(cards_layout)

        # --- Severity Dağılımı ---
        sev_frame = QFrame()
        sev_frame.setStyleSheet("""
            QFrame {
                background-color: #0d0d0d;
                border: 1px solid #330000;
                border-radius: 6px;
            }
        """)
        sev_layout = QGridLayout(sev_frame)
        sev_layout.addWidget(QLabel("<b style='color:#ff2b2b;'>Severity Dağılımı</b>"), 0, 0, 1, 4)

        self.severity_labels = {}
        severities = [
            ("Kritik", "#ff0000"),
            ("Yüksek", "#ff6600"),
            ("Orta",   "#ffaa00"),
            ("Düşük",  "#00aaff"),
        ]
        for col, (name, color) in enumerate(severities):
            lbl = QLabel(f"{name}: 0")
            lbl.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: bold;")
            lbl.setAlignment(Qt.AlignCenter)
            sev_layout.addWidget(lbl, 1, col)
            self.severity_labels[name] = lbl

        layout.addWidget(sev_frame)

        # --- Son Taramalar Tablosu ---
        recent_title = QLabel("Son Taramalar")
        recent_title.setStyleSheet("color: #ff2b2b; font-size: 14px; font-weight: bold;")
        layout.addWidget(recent_title)

        self.recent_table = QTableWidget(0, 4)
        self.recent_table.setHorizontalHeaderLabels(["Hedef", "Tarih", "Bulgu", "Durum"])
        self.recent_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.recent_table.setStyleSheet("""
            QTableWidget {
                background-color: #0d0d0d;
                color: #ddd;
                border: 1px solid #330000;
                gridline-color: #330000;
            }
            QHeaderView::section {
                background-color: #1a0000;
                color: #ff2b2b;
                border: 1px solid #330000;
                padding: 4px;
            }
        """)
        layout.addWidget(self.recent_table)

    # --- Dışarıdan çağrılacak metodlar ---
    def update_stats(self, targets=None, vulns=None, modules=None, critical=None):
        if targets is not None:  self.card_targets.set_value(targets)
        if vulns is not None:    self.card_vulns.set_value(vulns)
        if modules is not None:  self.card_modules.set_value(modules)
        if critical is not None: self.card_critical.set_value(critical)

    def update_severity(self, critical=0, high=0, medium=0, low=0):
        self.severity_labels["Kritik"].setText(f"Kritik: {critical}")
        self.severity_labels["Yüksek"].setText(f"Yüksek: {high}")
        self.severity_labels["Orta"].setText(f"Orta: {medium}")
        self.severity_labels["Düşük"].setText(f"Düşük: {low}")

    def add_scan_record(self, target, date, findings, status):
        row = self.recent_table.rowCount()
        self.recent_table.insertRow(row)
        self.recent_table.setItem(row, 0, QTableWidgetItem(target))
        self.recent_table.setItem(row, 1, QTableWidgetItem(date))
        self.recent_table.setItem(row, 2, QTableWidgetItem(str(findings)))
        self.recent_table.setItem(row, 3, QTableWidgetItem(status))