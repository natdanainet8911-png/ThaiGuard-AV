"""ThaiGuard AV — จุดเริ่มต้นโปรแกรม"""
import sys
from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

from config import ensure_dirs, APP_NAME, APP_VERSION


def main():
    ensure_dirs()

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("Tools Development Project")

    try:
        from ui.main_window import MainWindow
        win = MainWindow()
        win.show()
    except Exception as e:
        QMessageBox.critical(None, "เริ่มโปรแกรมไม่สำเร็จ",
                             f"เกิดข้อผิดพลาด:\n{e}")
        raise

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
