from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QHBoxLayout

class TerminalView(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Canlı Log Alanı
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setPlaceholderText("[*] Sistem logları ve çıktı konsolu burada akacak...")
        layout.addWidget(self.console)

        # Alt Kontroller
        btn_layout = QHBoxLayout()
        self.clear_btn = QPushButton("Konsolu Temizle")
        self.clear_btn.clicked.connect(self.console.clear)
        
        btn_layout.addStretch()
        btn_layout.addWidget(self.clear_btn)
        layout.addLayout(btn_layout)