"""Scan Engine + Worker Thread"""
import os
import time
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal

from config import (ENGINE_WEIGHTS, RISK_HIGH, RISK_MEDIUM,
                    MAX_SCAN_SIZE, DATA_DIR)
from core.hasher import hash_file
from core.heuristic import analyze as heuristic_analyze
from core.yara_engine import YaraEngine

HEAD_BYTES = 2 * 1024 * 1024      # อ่านส่วนหัวไฟล์ 2 MB มาวิเคราะห์


class ScanEngine:
    """รวมผลจากทุก engine แล้วให้คำตัดสิน"""

    def __init__(self, db, yara_engine: YaraEngine | None = None):
        self.db = db
        self.yara = yara_engine or YaraEngine()

    # ------------------------------------------------------------------
    def scan_file(self, path: str) -> dict:
        p = Path(path)
        base = {
            "path": str(p), "name": p.name, "size": 0, "sha256": "", "md5": "",
            "verdict": "CLEAN", "risk_score": 0.0, "detection": "",
            "reasons": [], "engines": {}, "entropy": 0.0,
        }

        try:
            size = p.stat().st_size
            base["size"] = size
            if size == 0:
                base["verdict"] = "CLEAN"
                return base
            if size > MAX_SCAN_SIZE:
                base["verdict"] = "SKIPPED"
                base["reasons"] = [f"ไฟล์ใหญ่เกิน {MAX_SCAN_SIZE // (1024*1024)} MB"]
                return base

            # ---------- 1) Signature ----------
            hashes = hash_file(p)
            base.update(sha256=hashes["sha256"], md5=hashes["md5"])
            sig_score, sig_reasons, detection = 0, [], ""
            hit = self.db.lookup_signature(hashes["sha256"])
            if hit:
                sig_score = hit["severity"]
                detection = hit["name"]
                sig_reasons = [f"ตรงกับลายเซ็นในฐานข้อมูล: {hit['name']}"]
            base["engines"]["signature"] = {"score": sig_score, "reasons": sig_reasons}

            # ---------- 2) อ่านส่วนหัวไฟล์ ----------
            with open(p, "rb") as f:
                head = f.read(HEAD_BYTES)

            # ---------- 3) YARA ----------
            y = self.yara.scan(str(p), head if size <= HEAD_BYTES else None)
            base["engines"]["yara"] = y
            if y["matches"] and not detection:
                detection = f"YARA/{y['matches'][0]}"

            # ---------- 4) Heuristic ----------
            h = heuristic_analyze(str(p), head)
            base["engines"]["heuristic"] = h
            base["entropy"] = h["entropy"]
            if h["score"] >= 50 and not detection:
                detection = "Heuristic/Suspicious.Generic"

            # ---------- 5) รวมคะแนน ----------
            total = sum(base["engines"][k]["score"] * w
                        for k, w in ENGINE_WEIGHTS.items() if k in base["engines"])

            # ถ้า signature ชนเต็ม ๆ ให้ถือเป็นอันตรายทันที
            if sig_score >= 90:
                total = 100.0

            base["risk_score"] = round(min(total, 100.0), 1)
            base["reasons"] = (sig_reasons + y["reasons"] + h["reasons"])[:8]

            if base["risk_score"] >= RISK_HIGH:
                base["verdict"] = "MALICIOUS"
            elif base["risk_score"] >= RISK_MEDIUM:
                base["verdict"] = "SUSPICIOUS"
            else:
                base["verdict"] = "CLEAN"

            base["detection"] = detection or ("-" if base["verdict"] == "CLEAN" else "Generic.Suspicious")

        except (PermissionError, OSError) as e:
            base["verdict"] = "ERROR"
            base["reasons"] = [f"เข้าถึงไฟล์ไม่ได้: {e.__class__.__name__}"]
        except Exception as e:
            base["verdict"] = "ERROR"
            base["reasons"] = [f"เกิดข้อผิดพลาด: {e}"]

        return base


# ======================================================================
class ScanWorker(QThread):
    """เธรดสแกน — ไม่ให้ UI ค้าง"""

    progress   = pyqtSignal(int, int, str)   # done, total, current_file
    counting   = pyqtSignal(int)             # จำนวนไฟล์ที่นับได้
    result     = pyqtSignal(dict)            # ผลรายไฟล์
    finished_s = pyqtSignal(dict)            # สรุปผล
    message    = pyqtSignal(str)

    def __init__(self, engine: ScanEngine, targets: list[str], scan_id: int,
                 emit_clean: bool = False, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.targets = targets
        self.scan_id = scan_id
        self.emit_clean = emit_clean
        self._stop = False
        self._pause = False

    # ------------------------------------------------------------------
    def stop(self):
        self._stop = True
        self._pause = False

    def toggle_pause(self) -> bool:
        self._pause = not self._pause
        return self._pause

    # ------------------------------------------------------------------
    def _iter_files(self):
        skip_dirs = {str(DATA_DIR).lower(), "\\windows\\winsxs", "/proc", "/sys", "/dev"}
        for t in self.targets:
            tp = Path(t)
            if tp.is_file():
                yield str(tp)
            elif tp.is_dir():
                for root, dirs, files in os.walk(tp, topdown=True, onerror=lambda e: None):
                    rl = root.lower()
                    if any(s in rl for s in skip_dirs):
                        dirs[:] = []
                        continue
                    dirs[:] = [d for d in dirs if not d.startswith(("$", "."))]
                    for fn in files:
                        yield os.path.join(root, fn)

    # ------------------------------------------------------------------
    def run(self):
        t0 = time.time()
        self.message.emit("กำลังสำรวจไฟล์...")
        all_files = []
        for fp in self._iter_files():
            if self._stop:
                break
            all_files.append(fp)
            if len(all_files) % 500 == 0:
                self.counting.emit(len(all_files))

        total = len(all_files)
        self.counting.emit(total)
        self.message.emit(f"เริ่มสแกน {total:,} ไฟล์")

        summary = {"total": 0, "threats": 0, "suspicious": 0,
                   "clean": 0, "errors": 0, "skipped": 0, "duration": 0}

        for i, fp in enumerate(all_files, 1):
            if self._stop:
                break
            while self._pause and not self._stop:
                self.msleep(150)

            self.progress.emit(i, total, fp)
            r = self.engine.scan_file(fp)
            summary["total"] += 1

            v = r["verdict"]
            if v == "MALICIOUS":
                summary["threats"] += 1
            elif v == "SUSPICIOUS":
                summary["suspicious"] += 1
            elif v == "ERROR":
                summary["errors"] += 1
            elif v == "SKIPPED":
                summary["skipped"] += 1
            else:
                summary["clean"] += 1

            if v in ("MALICIOUS", "SUSPICIOUS"):
                try:
                    self.engine.db.add_detection(self.scan_id, r)
                except Exception:
                    pass

            if v in ("MALICIOUS", "SUSPICIOUS") or self.emit_clean:
                self.result.emit(r)

        summary["duration"] = round(time.time() - t0, 2)
        summary["stopped"] = self._stop
        self.finished_s.emit(summary)
