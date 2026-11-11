import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
from PySide6.QtCore import Qt

class AgentWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PentaGen Desktop Agent")
        self.resize(560, 320)
        title = QLabel("PentaGen Desktop Agent")
        title.setStyleSheet("font-size:24px;font-weight:700;color:#dce7fa")
        status = QLabel("Agent scaffold ready. Secure pairing and signed job verification are not implemented yet.")
        status.setWordWrap(True)
        status.setStyleSheet("color:#9aabc4;font-size:14px")
        note = QLabel("Do not connect this agent to untrusted orchestration servers.")
        note.setStyleSheet("color:#f0bd65")
        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addWidget(status)
        layout.addWidget(note)
        layout.addStretch()
        root = QWidget(); root.setLayout(layout)
        root.setStyleSheet("background:#0b1424;padding:28px")
        self.setCentralWidget(root)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AgentWindow()
    window.show()
    sys.exit(app.exec())
