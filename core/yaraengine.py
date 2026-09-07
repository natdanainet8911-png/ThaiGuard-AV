"""ตัวห่อหุ้ม YARA — รองรับทั้ง yara-python (คลาสสิก) และ yara-x (Rust)"""
from pathlib import Path
from config import RULES_DIR

BACKEND = None
try:
    import yara as _yara
    BACKEND = "yara-python"
except ImportError:
    try:
        import yara_x as _yarax
        BACKEND = "yara-x"
    except ImportError:
        BACKEND = None


class YaraEngine:
    def __init__(self, rules_dir: Path = RULES_DIR):
        self.rules_dir = Path(rules_dir)
        self.rules = None
        self.rule_count = 0
        self.error = None
        self.backend = BACKEND
        self.reload()

    # ------------------------------------------------------------------
    def available(self) -> bool:
        return self.rules is not None

    def reload(self):
        self.rules, self.error, self.rule_count = None, None, 0
        if BACKEND is None:
            self.error = "ยังไม่ได้ติดตั้ง YARA (pip install yara-python หรือ yara-x)"
            return

        files = sorted(self.rules_dir.glob("*.yar")) + sorted(self.rules_dir.glob("*.yara"))
        if not files:
            self.error = f"ไม่พบไฟล์กฎในโฟลเดอร์ {self.rules_dir}"
            return

        try:
            if BACKEND == "yara-python":
                self.rules = _yara.compile(
                    filepaths={f.stem: str(f) for f in files})
            else:  # yara-x
                compiler = _yarax.Compiler()
                for f in files:
                    compiler.add_source(f.read_text(encoding="utf-8", errors="ignore"))
                self.rules = compiler.build()

            self.rule_count = sum(
                sum(1 for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if ln.strip().startswith("rule "))
                for f in files)
        except Exception as e:
            self.error = f"คอมไพล์กฎไม่สำเร็จ: {e}"
            self.rules = None

    # ------------------------------------------------------------------
    def scan(self, filepath: str, data: bytes | None = None) -> dict:
        """คืน {'score': int, 'matches': [ชื่อกฎ], 'reasons': [...]}"""
        empty = {"score": 0, "matches": [], "reasons": []}
        if not self.available():
            return empty

        try:
            if BACKEND == "yara-python":
                hits = self.rules.match(filepath=filepath, timeout=20)
                names = [m.rule for m in hits]
                metas = [m.meta for m in hits]
            else:
                if data is None:
                    data = Path(filepath).read_bytes()
                result = self.rules.scan(data)
                names = [r.identifier for r in result.matching_rules]
                metas = [{} for _ in names]
        except Exception:
            return empty

        if not names:
            return empty

        score, reasons = 0, []
        for name, meta in zip(names, metas):
            sev = str(meta.get("severity", "medium")).lower()
            pts = {"critical": 60, "high": 45, "medium": 30, "low": 15}.get(sev, 30)
            score += pts
            desc = meta.get("description", "")
            reasons.append(f"ตรงกับกฎ YARA: {name}" + (f" — {desc}" if desc else ""))

        return {"score": min(score, 100), "matches": names, "reasons": reasons}
