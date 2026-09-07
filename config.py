"""ค่าคงที่และ path ทั้งหมดของระบบ"""
from pathlib import Path

APP_NAME = "ThaiGuard AV"
APP_VERSION = "1.0.0"
APP_AUTHOR = "โครงงานพัฒนาเครื่องมือ - Tools Development"

BASE_DIR       = Path(__file__).resolve().parent
DATA_DIR       = BASE_DIR / "data"
RULES_DIR      = BASE_DIR / "rules"
QUARANTINE_DIR = DATA_DIR / "quarantine"
LOG_DIR        = DATA_DIR / "logs"
DB_PATH        = DATA_DIR / "thaiguard.db"

# กุญแจ XOR สำหรับ "ทำให้ไฟล์กักกันรันไม่ได้" (เพื่อการศึกษา ไม่ใช่ crypto จริง)
QUARANTINE_KEY = b"ThaiGuardAV-Quarantine-Key-2026!"

MAX_SCAN_SIZE = 150 * 1024 * 1024        # ข้ามไฟล์ใหญ่เกิน 150 MB
READ_CHUNK    = 1024 * 1024              # อ่านทีละ 1 MB

# น้ำหนักของแต่ละ engine ในการคำนวณ Risk Score
ENGINE_WEIGHTS = {
    "signature": 0.45,
    "yara":      0.30,
    "heuristic": 0.25,
}

RISK_HIGH   = 70     # >= 70  -> อันตราย
RISK_MEDIUM = 40     # >= 40  -> น่าสงสัย

# นามสกุลที่ถือว่า "รันได้" -> ให้คะแนนความเสี่ยงพิเศษ
EXECUTABLE_EXT = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd",
    ".vbs", ".vbe", ".js", ".jse", ".ps1", ".psm1", ".hta",
    ".jar", ".msi", ".wsf", ".lnk", ".sys", ".cpl",
}

DEFAULT_SETTINGS = {
    "scan_archives":     False,
    "show_clean_files":  False,
    "auto_quarantine":   False,
    "realtime_enabled":  False,
    "realtime_folder":   str(Path.home() / "Downloads"),
    "max_file_size_mb":  150,
}


def ensure_dirs() -> None:
    for d in (DATA_DIR, RULES_DIR, QUARANTINE_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)
