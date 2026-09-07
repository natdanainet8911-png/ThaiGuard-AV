"""คำนวณค่าแฮชของไฟล์แบบ streaming (รองรับไฟล์ขนาดใหญ่)"""
import hashlib
from pathlib import Path
from config import READ_CHUNK


def hash_file(path: str | Path) -> dict:
    """คืน dict {'md5':..., 'sha1':..., 'sha256':..., 'size':...}"""
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(READ_CHUNK):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size": size,
    }


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()
