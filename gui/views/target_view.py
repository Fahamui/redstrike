from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtCore import Qt
import webbrowser
from core.engine import RedStrikeEngine

class TargetView(QWidget):
    def __init__(self):
        super().__init__()
        self.engine = None
        self.console_widget = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Hedef:"))
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://ornek.com")
        top_layout.addWidget(self.target_input)

        self.start_btn = QPushButton("Taramayı Başlat")
        self.start_btn.clicked.connect(self.start_scan)
        top_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("İptal Et")
        self.stop_btn.setStyleSheet("background-color: #550000; color: white;")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        top_layout.addWidget(self.stop_btn)

        layout.addLayout(top_layout)

        layout.addWidget(QLabel("Tarama ve Keşif Sonuçları:"))

        self.result_table = QTableWidget()
        self.result_table.setColumnCount(3)
        self.result_table.setHorizontalHeaderLabels(["Modül", "Bulgu / Detay", "Durum"])
        
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        
        self.result_table.setColumnWidth(0, 160)
        self.result_table.setColumnWidth(2, 160)
        
        self.result_table.itemDoubleClicked.connect(self.on_row_double_clicked)
        
        layout.addWidget(self.result_table)

    def set_console(self, console_widget):
        self.console_widget = console_widget

    def log_to_terminal(self, message):
        if self.console_widget:
            self.console_widget.append(message)

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            return

        self.result_table.setRowCount(0)
        self.start_btn.setEnabled(False)
        self.start_btn.setText("Taranıyor...")
        self.stop_btn.setEnabled(True)

        self.engine = RedStrikeEngine(target)
        self.engine.new_result.connect(self.add_result_row)
        self.engine.new_log.connect(self.log_to_terminal)
        self.engine.finished_scan.connect(self.scan_finished)
        self.engine.start()

    def stop_scan(self):
        if self.engine:
            self.engine.stop()
            self.scan_finished()

    def add_result_row(self, result):
        row_position = self.result_table.rowCount()
        self.result_table.insertRow(row_position)
        
        self.result_table.setItem(row_position, 0, QTableWidgetItem(result.get("module", "")))
        self.result_table.setItem(row_position, 1, QTableWidgetItem(result.get("detail", "")))
        self.result_table.setItem(row_position, 2, QTableWidgetItem(result.get("status", "")))

    def on_row_double_clicked(self, item):
        row = item.row()
        detail_item = self.result_table.item(row, 1)
        if detail_item:
            text = detail_item.text()
            url = text.split(" ")[0]
            if url.startswith("http://") or url.startswith("https://"):
                webbrowser.open(url)
                if self.console_widget:
                    self.console_widget.append(f"[*] Tarayıcıda açılıyor: {url}")

    def scan_finished(self):
        self.start_btn.setEnabled(True)
        self.start_btn.setText("Taramayı Başlat")
        self.stop_btn.setEnabled(False)
        if self.engine:
            self.engine = None