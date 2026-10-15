from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QWidget,
    QTextEdit, QSplitter, QLabel
)
from PySide6.QtCore import Qt

from gui.views.dashboard_view import DashboardView
from gui.views.target_view import TargetView
from gui.views.settings_view import SettingsView


class LogConsole(QTextEdit):
    """Ortak log konsolu — tüm sekmeler bunu kullanır."""
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setStyleSheet("""
            background-color: #0b0b0b;
            color: #00ff66;
            font-family: Consolas, monospace;
            font-size: 13px;
            border: none;
            padding: 8px;
        """)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Suite - Modular Framework")
        self.resize(1100, 750)

        # Ortak log buffer
        self.log_buffer = []

        self.init_ui()

    # ============================================================
    # ORTAK LOG FONKSİYONU
    # ============================================================
    def log(self, message):
        """Tüm konsollara log bas."""
        self.log_buffer.append(message)
        if hasattr(self, "dashboard_console"):
            self.dashboard_console.append(message)
        if hasattr(self, "target_console"):
            self.target_console.append(message)

    

    # ============================================================
    # UI
    # ============================================================
    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # ============================================
        # 1. SEKME: DASHBOARD + TERMINAL
        # ============================================
        dashboard_tab = QWidget()
        dash_layout = QVBoxLayout(dashboard_tab)
        dash_layout.setContentsMargins(0, 0, 0, 0)
        dash_layout.setSpacing(0)

        dash_splitter = QSplitter(Qt.Vertical)
        dash_splitter.setHandleWidth(6)
        self.style_splitter(dash_splitter)

        # Üst: Dashboard
        self.dashboard_view = DashboardView()
        dash_splitter.addWidget(self.dashboard_view)

        # Alt: Terminal
        dash_terminal = self.create_terminal_container()
        self.dashboard_console = dash_terminal["console"]
        dash_splitter.addWidget(dash_terminal["widget"])

        dash_splitter.setSizes([500, 250])
        self.dashboard_view.setMinimumHeight(200)

        dash_layout.addWidget(dash_splitter)
        self.tabs.addTab(dashboard_tab, "Dashboard")

        # ============================================
        # 2. SEKME: HEDEF / TARAMA + TERMINAL
        # ============================================
        target_tab = QWidget()
        target_layout = QVBoxLayout(target_tab)
        target_layout.setContentsMargins(0, 0, 0, 0)
        target_layout.setSpacing(0)

        target_splitter = QSplitter(Qt.Vertical)
        target_splitter.setHandleWidth(6)
        self.style_splitter(target_splitter)

        # Üst: Target View
        self.target_view = TargetView()
        target_splitter.addWidget(self.target_view)

        # Alt: Terminal
        target_terminal = self.create_terminal_container()
        self.target_console = target_terminal["console"]
        target_splitter.addWidget(target_terminal["widget"])

        target_splitter.setSizes([500, 250])
        self.target_view.setMinimumHeight(300)

        target_layout.addWidget(target_splitter)
        self.tabs.addTab(target_tab, "Hedef / Tarama")

        # ============================================
        # 3. SEKME: AYARLAR
        # ============================================
        self.settings_view = SettingsView()
        self.tabs.addTab(self.settings_view, "Ayarlar")

        # ============================================
        # BAĞLANTILAR
        # ============================================
        # Target view → paylaşımlı logger (her iki konsola basar)
        self.target_view.set_shared_logger(self.log)

        # Hoş geldin mesajı
        self.log("[+] RedStrike Suite v1.0 başlatıldı.")
        self.log("[*] Tüm sekmelerde aynı log akışı görünür.")

    # ============================================================
    # YARDIMCI
    # ============================================================
    def create_terminal_container(self):
        """Terminal konteyneri oluştur (başlık + konsol)."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Başlık
        header = QLabel("  💻  Terminal / Konsol")
        header.setStyleSheet("""
            background-color: #1a0000;
            color: #ff2b2b;
            font-weight: bold;
            font-size: 12px;
            padding: 6px 10px;
            border-bottom: 1px solid #4d0000;
        """)
        layout.addWidget(header)

        # Konsol
        console = LogConsole()
        layout.addWidget(console)

        return {"widget": container, "console": console}

    def style_splitter(self, splitter):
        """Splitter stilini ayarla."""
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #1a0000;
                border-top: 1px solid #4d0000;
                border-bottom: 1px solid #4d0000;
            }
            QSplitter::handle:hover {
                background-color: #ff2b2b;
            }
        """)