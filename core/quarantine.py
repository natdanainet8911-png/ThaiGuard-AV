"""ระบบกักกันไฟล์ — เข้ารหัส XOR + เปลี่ยนนามสกุล เพื่อให้ไฟล์รันไม่ได้"""
import os
import shutil
import uuid
from pathlib import Path
from config import QUARANTINE_DIR, QUARANTINE_KEY, READ_CHUNK

QUAR_EXT = ".tgq"      # ThaiGuard Quarantine


def _xor_copy(src: Path, dst: Path, key: bytes) -> None:
    """คัดลอกพร้อม XOR ทีละ chunk (ทำงานได้ทั้งเข้ารหัสและถอดรหัส)"""
    klen = len(key)
    offset = 0
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while chunk := fi.read(READ_CHUNK):
            fo.write(bytes(b ^ key[(offset + i) % klen] for i, b in enumerate(chunk)))
            offset += len(chunk)


class QuarantineManager:
    def __init__(self, db, folder: Path = QUARANTINE_DIR):
        self.db = db
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    def quarantine(self, result: dict) -> tuple[bool, str]:
        src = Path(result["path"])
        if not src.exists():
            return False, "ไม่พบไฟล์ต้นทาง (อาจถูกย้าย/ลบไปแล้ว)"
        try:
            stored = f"{uuid.uuid4().hex}{QUAR_EXT}"
            dst = self.folder / stored
            _xor_copy(src, dst, QUARANTINE_KEY)

            # ลบต้นฉบับ — ถ้าลบไม่ได้ให้ถอยกลับ ไม่ทิ้งไฟล์ค้าง
            try:
                os.remove(src)
            except PermissionError:
                dst.unlink(missing_ok=True)
                return False, "ลบไฟล์ต้นฉบับไม่ได้ (ไฟล์กำลังถูกใช้งาน หรือไม่มีสิทธิ์)"

            self.db.add_quarantine({
                "original_path": str(src),
                "stored_name": stored,
                "sha256": result.get("sha256", ""),
                "detection": result.get("detection", "Unknown"),
                "risk_score": result.get("risk_score", 0),
                "size": result.get("size", 0),
            })
            return True, f"กักกันเรียบร้อย: {src.name}"
        except Exception as e:
            return False, f"กักกันไม่สำเร็จ: {e}"

    # ------------------------------------------------------------------
    def restore(self, qid: int, target_dir: str | None = None) -> tuple[bool, str]:
        rec = self.db.get_quarantine(qid)
        if not rec:
            return False, "ไม่พบรายการกักกันนี้"

        stored = self.folder / rec["stored_name"]
        if not stored.exists():
            return False, "ไฟล์ในโฟลเดอร์กักกันหายไป"

        original = Path(rec["original_path"])
        dest = Path(target_dir) / original.name if target_dir else original

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                dest = dest.with_name(f"{dest.stem}_restored{dest.suffix}")
            _xor_copy(stored, dest, QUARANTINE_KEY)
            stored.unlink(missing_ok=True)
            self.db.delete_quarantine(qid)
            return True, f"กู้คืนไปที่: {dest}"
        except Exception as e:
            return False, f"กู้คืนไม่สำเร็จ: {e}"

    # ------------------------------------------------------------------
    def delete_permanently(self, qid: int) -> tuple[bool, str]:
        rec = self.db.get_quarantine(qid)
        if not rec:
            return False, "ไม่พบรายการ"
        try:
            (self.folder / rec["stored_name"]).unlink(missing_ok=True)
            self.db.delete_quarantine(qid)
            return True, "ลบถาวรเรียบร้อย"
        except Exception as e:
            return False, f"ลบไม่สำเร็จ: {e}"

    def empty_all(self) -> int:
        n = 0
        for rec in self.db.list_quarantine():
            ok, _ = self.delete_permanently(rec["id"])
            n += 1 if ok else 0
        return n
