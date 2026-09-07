"""Heuristic Engine — วิเคราะห์โครงสร้าง/เนื้อหาไฟล์เพื่อหาความผิดปกติ"""
import math
import re
from collections import Counter
from pathlib import Path
from config import EXECUTABLE_EXT

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

# ---- API ของ Windows ที่มัลแวร์นิยมใช้ (ใช้เป็นตัวชี้วัด ไม่ใช่หลักฐานเด็ดขาด) ----
SUSPICIOUS_APIS = {
    "CreateRemoteThread": 18, "WriteProcessMemory": 18, "VirtualAllocEx": 15,
    "NtUnmapViewOfSection": 20, "SetWindowsHookExA": 15, "SetWindowsHookExW": 15,
    "GetAsyncKeyState": 14, "URLDownloadToFileA": 16, "URLDownloadToFileW": 16,
    "InternetOpenUrlA": 10, "WinExec": 10, "IsDebuggerPresent": 12,
    "CheckRemoteDebuggerPresent": 12, "CryptEncrypt": 10, "AdjustTokenPrivileges": 8,
    "OpenProcessToken": 6, "ShellExecuteA": 6, "CreateToolhelp32Snapshot": 8,
}

# ---- Pattern ในเนื้อไฟล์ที่บ่งชี้พฤติกรรมอันตราย ----
SUSPICIOUS_PATTERNS = [
    (rb"powershell[^\n]{0,40}-[eE]nc(odedCommand)?", "PowerShell แบบเข้ารหัส Base64", 30),
    (rb"-WindowStyle\s+[Hh]idden",                   "สั่งรันแบบซ่อนหน้าต่าง", 22),
    (rb"-ExecutionPolicy\s+Bypass",                  "ข้าม Execution Policy", 22),
    (rb"DownloadString|DownloadFile|Invoke-WebRequest", "ดาวน์โหลดไฟล์จากอินเทอร์เน็ต", 18),
    (rb"Invoke-Expression|IEX\s*\(",                 "รันคำสั่งจากสตริง (IEX)", 20),
    (rb"vssadmin[^\n]{0,30}delete\s+shadows",        "ลบ Shadow Copy (พฤติกรรม Ransomware)", 45),
    (rb"bcdedit[^\n]{0,40}recoveryenabled\s+no",     "ปิดระบบกู้คืน Windows", 40),
    (rb"cipher\s*/w",                                "ลบข้อมูลถาวร", 25),
    (rb"schtasks[^\n]{0,20}/create",                 "สร้าง Scheduled Task (คงอยู่ในระบบ)", 18),
    (rb"reg\s+add[^\n]{0,60}CurrentVersion\\\\?Run", "เขียน Registry Run Key (Autostart)", 25),
    (rb"netsh\s+firewall|netsh\s+advfirewall",       "แก้ไขค่า Firewall", 15),
    (rb"[Bb]itcoin|[Mm]onero|wallet address",        "พบข้อความเกี่ยวกับคริปโต (เรียกค่าไถ่?)", 12),
    (rb"YOUR FILES (HAVE BEEN|ARE) ENCRYPTED",       "ข้อความเรียกค่าไถ่", 50),
    (rb"eval\s*\(\s*(base64_decode|gzinflate)",      "โค้ดเว็บที่ถูกซ่อน (Web Shell)", 40),
]

DOUBLE_EXT_RE = re.compile(
    r"\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|txt|mp3|mp4|zip)\."
    r"(exe|scr|com|pif|bat|cmd|vbs|js|jar|lnk)$", re.IGNORECASE)


def shannon_entropy(data: bytes) -> float:
    """ค่าเอนโทรปี 0–8 : ยิ่งสูง = ยิ่งสุ่ม (บีบอัด/เข้ารหัส/packed)"""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _analyze_pe(path: str) -> tuple[int, list[str]]:
    """วิเคราะห์ไฟล์ PE (.exe/.dll) — คืน (คะแนน, เหตุผล)"""
    if not HAS_PEFILE:
        return 0, []
    score, reasons = 0, []
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])

        found = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if not imp.name:
                    continue
                api = imp.name.decode(errors="ignore")
                if api in SUSPICIOUS_APIS:
                    found.append(api)
        if found:
            uniq = sorted(set(found))
            score += min(sum(SUSPICIOUS_APIS[a] for a in uniq), 55)
            reasons.append("เรียกใช้ API ที่น่าสงสัย: " + ", ".join(uniq[:6]))

        # section ที่ entropy สูง = อาจถูก pack
        for sec in pe.sections:
            name = sec.Name.decode(errors="ignore").rstrip("\x00")
            ent = sec.get_entropy()
            if ent > 7.4 and sec.SizeOfRawData > 1024:
                score += 18
                reasons.append(f"Section '{name}' entropy สูง ({ent:.2f}) — น่าจะถูก pack")
                break

        # ไม่มี import table เลย = พฤติกรรมของ packer
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            score += 15
            reasons.append("ไม่พบ Import Table (ลักษณะของไฟล์ที่ถูก pack)")

        pe.close()
    except Exception:
        pass
    return score, reasons


def analyze(path: str, head: bytes) -> dict:
    """
    วิเคราะห์ heuristic ทั้งหมด
    :param head: ไบต์ส่วนต้นของไฟล์ (สูงสุด ~2 MB) เพื่อไม่ให้กินหน่วยความจำ
    """
    p = Path(path)
    score, reasons = 0, []
    ext = p.suffix.lower()

    # 1) นามสกุลไฟล์ซ้อน
    if DOUBLE_EXT_RE.search(p.name):
        score += 55
        reasons.append(f"นามสกุลไฟล์ซ้อนเพื่อหลอกผู้ใช้: {p.name}")

    # 2) เอนโทรปี
    ent = shannon_entropy(head[:1024 * 512])
    if ent > 7.5 and ext in EXECUTABLE_EXT:
        score += 30
        reasons.append(f"เอนโทรปีสูงมาก ({ent:.2f}/8.00) — ไฟล์อาจถูกเข้ารหัส/บีบอัด")
    elif ent > 7.2 and ext in EXECUTABLE_EXT:
        score += 15
        reasons.append(f"เอนโทรปีค่อนข้างสูง ({ent:.2f}/8.00)")

    # 3) ชนิดไฟล์จริง vs นามสกุล (Magic bytes)
    if head[:2] == b"MZ" and ext not in EXECUTABLE_EXT and ext not in ("", ".bin", ".dat"):
        score += 45
        reasons.append(f"ไฟล์เป็น Windows Executable แต่ใช้นามสกุล '{ext}' อำพราง")

    # 4) Pattern ในเนื้อไฟล์
    sample = head[:1024 * 1024]
    for pattern, desc, pts in SUSPICIOUS_PATTERNS:
        if re.search(pattern, sample):
            score += pts
            reasons.append(f"พบรูปแบบน่าสงสัย: {desc}")

    # 5) วิเคราะห์ PE เชิงลึก
    if head[:2] == b"MZ":
        pe_score, pe_reasons = _analyze_pe(path)
        score += pe_score
        reasons.extend(pe_reasons)

    # 6) ไฟล์รันได้ที่ซ่อนอยู่ในโฟลเดอร์ชั่วคราว
    low = str(p).lower()
    if ext in EXECUTABLE_EXT and any(k in low for k in ("\\temp\\", "/tmp/", "appdata\\local\\temp")):
        score += 12
        reasons.append("ไฟล์รันได้อยู่ในโฟลเดอร์ชั่วคราว")

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "entropy": round(ent, 3),
    }
