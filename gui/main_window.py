from PySide6.QtWidgets import QMainWindow, QTabWidget, QVBoxLayout, QWidget, QTextEdit, QLabel
from gui.views.target_view import TargetView
from gui.views.settings_view import SettingsView

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Suite - Modular Framework")
        self.resize(1100, 750)
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Sekme Yöneticisi
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 1. Sekme: Dashboard
        self.dashboard_tab = QWidget()
        dash_layout = QVBoxLayout(self.dashboard_tab)
        dash_layout.addWidget(QLabel("<h2>RedStrike Suite v1.0</h2><p>Modüler Güvenlik Keşif ve Analiz Framework'üne Hoş Geldiniz.</p>"))
        self.tabs.addTab(self.dashboard_tab, "Dashboard")

        # 2. Sekme: Hedef ve Tarama Arayüzü
        self.target_view = TargetView()
        self.tabs.addTab(self.target_view, "Hedef / Tarama")

        # 3. Sekme: Canlı Terminal / Konsol Ekranı (Yerinde duruyor)
        self.terminal_tab = QWidget()
        terminal_layout = QVBoxLayout(self.terminal_tab)
        
        self.terminal_console = QTextEdit()
        self.terminal_console.setReadOnly(True)
        self.terminal_console.setStyleSheet("""
            background-color: #0b0b0b; 
            color: #00ff66; 
            font-family: Consolas, monospace; 
            font-size: 13px;
        """)
        terminal_layout.addWidget(self.terminal_console)
        self.tabs.addTab(self.terminal_tab, "Terminal / Konsol")

        # 4. Sekme: Ayarlar
        self.settings_view = SettingsView()
        self.tabs.addTab(self.settings_view, "Ayarlar")

        # Konsol bağlantısı aktif
        self.target_view.set_console(self.terminal_console)