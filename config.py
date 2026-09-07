"""ค่าคงที่และ path ทั้งหมด — รองรับทั้งโหมด dev และโหมด .exe (frozen)"""
import os
import shutil
import sys
from pathlib import Path

APP_NAME    = "ThaiGuard AV"
APP_VERSION = "1.0.0"
APP_AUTHOR  = "โครงงานพัฒนาเครื่องมือ (Tools Development)"

# ── โหมดพกพา: True = เก็บข้อมูลข้าง ๆ .exe | False = เก็บใน %LOCALAPPDATA% ──
PORTABLE_MODE = True


def is_frozen() -> bool:
    """True เมื่อกำลังรันเป็นไฟล์ .exe ที่ PyInstaller สร้าง"""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


# ---------- โฟลเดอร์ทรัพยากรที่แพ็กมากับโปรแกรม (อ่านอย่างเดียว) ----------
if is_frozen():
    BUNDLE_DIR = Path(sys._MEIPASS)                  # temp ที่ PyInstaller แตกไฟล์
    EXE_DIR    = Path(sys.executable).resolve().parent
else:
    BUNDLE_DIR = Path(__file__).resolve().parent
    EXE_DIR    = BUNDLE_DIR

BUNDLED_RULES_DIR = BUNDLE_DIR / "rules"


# ---------- โฟลเดอร์ข้อมูลที่เขียนได้ (คงอยู่ถาวร) ----------
def _writable_root() -> Path:
    if not is_frozen():
        return EXE_DIR
    if PORTABLE_MODE:
        probe = EXE_DIR / ".write_test"
        try:                                          # ทดสอบว่าเขียนได้จริงไหม
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return EXE_DIR
        except (PermissionError, OSError):
            pass                                      # อยู่ใน Program Files -> ถอยไป AppData
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ThaiGuardAV"
    return Path.home() / ".thaiguardav"


APP_ROOT       = _writable_root()
DATA_DIR       = APP_ROOT / "data"
RULES_DIR      = APP_ROOT / "rules"          # ผู้ใช้เพิ่มกฎเองได้ที่นี่
QUARANTINE_DIR = DATA_DIR / "quarantine"
LOG_DIR        = DATA_DIR / "logs"
DB_PATH        = DATA_DIR / "thaiguard.db"

QUARANTINE_KEY = b"ThaiGuardAV-Quarantine-Key-2026!"

MAX_SCAN_SIZE = 150 * 1024 * 1024
READ_CHUNK    = 1024 * 1024

ENGINE_WEIGHTS = {"signature": 0.45, "yara": 0.30, "heuristic": 0.25}
RISK_HIGH   = 70
RISK_MEDIUM = 40

EXECUTABLE_EXT = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd",
    ".vbs", ".vbe", ".js", ".jse", ".ps1", ".psm1", ".hta",
    ".jar", ".msi", ".wsf", ".lnk", ".sys", ".cpl",
}

DEFAULT_SETTINGS = {
    "scan_archives":    False,
    "show_clean_files": False,
    "auto_quarantine":  False,
    "realtime_enabled": False,
    "realtime_folder":  str(Path.home() / "Downloads"),
    "max_file_size_mb": 150,
}


def resource_path(relative: str) -> Path:
    """คืน path ของทรัพยากรที่แพ็กมา (ไอคอน, กฎเริ่มต้น ฯลฯ)"""
    return BUNDLE_DIR / relative


def ensure_dirs() -> None:
    """สร้างโฟลเดอร์ + คัดลอกกฎเริ่มต้นออกมาให้ผู้ใช้แก้ไขได้ (ทำครั้งแรกครั้งเดียว)"""
    for d in (DATA_DIR, RULES_DIR, QUARANTINE_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)

    if BUNDLED_RULES_DIR.exists() and BUNDLED_RULES_DIR != RULES_DIR:
        for src in list(BUNDLED_RULES_DIR.glob("*.yar")) + \
                   list(BUNDLED_RULES_DIR.glob("*.yara")):
            dst = RULES_DIR / src.name
            if not dst.exists():
                try:
                    shutil.copy2(src, dst)
                except Exception:
                    pass
