from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout, QFrame

class DashboardView(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        title = QLabel("<h2>Operasyon Paneli (Dashboard)</h2>")
        layout.addWidget(title)

        # Kartlar / İstatistik Alanı
        cards_layout = QHBoxLayout()
        
        self.card1 = self.create_card("Aktif Hedefler", "0")
        self.card2 = self.create_card("Bulunan Zafiyetler", "0")
        self.card3 = self.create_card("Çalışan Modüller", "Aktif")

        cards_layout.addWidget(self.card1)
        cards_layout.addWidget(self.card2)
        cards_layout.addWidget(self.card3)

        layout.addLayout(cards_layout)
        layout.addStretch()

    def create_card(self, title, value):
        frame = QFrame()
        frame.setStyleSheet("background-color: #121212; border: 1px solid #4d0000; border-radius: 5px;")
        v_layout = QVBoxLayout(frame)
        
        lbl_title = QLabel(f"<b>{title}</b>")
        lbl_value = QLabel(f"<h2>{value}</h2>")
        
        v_layout.addWidget(lbl_title)
        v_layout.addWidget(lbl_value)
        return frame