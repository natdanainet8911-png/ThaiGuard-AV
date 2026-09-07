"""เฝ้าดูโฟลเดอร์แบบเรียลไทม์ด้วย watchdog"""
from PyQt6.QtCore import QObject, pyqtSignal, QThread

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    FileSystemEventHandler = object


class _Handler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self.callback(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.callback(event.src_path)


class RealtimeMonitor(QObject):
    detected = pyqtSignal(dict)
    status   = pyqtSignal(str)

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.observer = None
        self.folder = None

    def available(self) -> bool:
        return HAS_WATCHDOG

    def start(self, folder: str) -> bool:
        if not HAS_WATCHDOG:
            self.status.emit("ยังไม่ได้ติดตั้ง watchdog (pip install watchdog)")
            return False
        self.stop()
        try:
            self.folder = folder
            self.observer = Observer()
            self.observer.schedule(_Handler(self._on_file), folder, recursive=True)
            self.observer.daemon = True
            self.observer.start()
            self.status.emit(f"🛡️ เปิดการป้องกันเรียลไทม์: {folder}")
            return True
        except Exception as e:
            self.status.emit(f"เปิดไม่สำเร็จ: {e}")
            return False

    def stop(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                pass
            self.observer = None
            self.status.emit("⏹️ ปิดการป้องกันเรียลไทม์แล้ว")

    def _on_file(self, path: str):
        QThread.msleep(400)          # รอให้เขียนไฟล์เสร็จ
        try:
            r = self.engine.scan_file(path)
            if r["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
                self.detected.emit(r)
        except Exception:
            pass
