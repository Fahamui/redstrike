import os
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QComboBox, QPushButton, QMessageBox
from PySide6.QtWidgets import QApplication

class SettingsView(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("<h3>Ayarlar ve Tema Yönetimi</h3>"))
        layout.addWidget(QLabel("Uygulama arayüzünün renk temasını buradan değiştirebilirsiniz:"))

        self.theme_combo = QComboBox()
        self.theme_combo.addItems([
            "Hacker Red (Kırmızı)",
            "Cyberpunk",
            "Matrix (Yeşil)",
            "Dark Theme (Koyu)",
            "Light Theme (Açık)"
        ])
        layout.addWidget(self.theme_combo)

        apply_btn = QPushButton("Temayı Uygula")
        apply_btn.clicked.connect(self.apply_theme)
        layout.addWidget(apply_btn)

        layout.addStretch()

    def apply_theme(self):
        selected = self.theme_combo.currentText()
        theme_map = {
            "Hacker Red (Kırmızı)": "hacker_red.qss",
            "Cyberpunk": "cyberpunk.qss",
            "Matrix (Yeşil)": "matrix.qss",
            "Dark Theme (Koyu)": "dark_theme.qss",
            "Light Theme (Açık)": "light_theme.qss"
        }
        
        filename = theme_map.get(selected, "hacker_red.qss")
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, "../../"))
        path = os.path.join(project_root, "gui", "styles", filename)

        app_instance = QApplication.instance()

        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                app_instance.setStyleSheet(f.read())
            QMessageBox.information(self, "Başarılı", f"Tema değiştirildi: {selected}")
        else:
            QMessageBox.warning(self, "Hata", f"Stil dosyası bulunamadı: {path}")