import sys
import os

# Proje ana dizinini Python arama yoluna zorla ekliyoruz
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from PySide6.QtWidgets import QApplication
from gui.main_window import MainWindow

def load_stylesheet(app, theme_name="hacker_red"):
    theme_paths = {
        "hacker_red": os.path.join(current_dir, "gui", "styles", "hacker_red.qss")
    }
    path = theme_paths.get(theme_name, theme_paths["hacker_red"])
    
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
        print(f"[+] Tema başarıyla yüklendi: {path}")
    else:
        print(f"[!] Stil dosyası bulunamadı: {path}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    load_stylesheet(app, "hacker_red")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())