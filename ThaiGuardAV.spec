# -*- mode: python ; coding: utf-8 -*-
"""ThaiGuard AV — PyInstaller spec (PyInstaller 6.x)"""
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

APP_NAME = "ThaiGuardAV"
ROOT = Path(SPECPATH)

hidden = [
    "yara",
    "yara_x",
    "pefile",
    "sqlite3",
] + collect_submodules("watchdog.observers")

# ตัดโมดูลที่ไม่ได้ใช้ออก -> ลดขนาดไฟล์ได้ 30–60 MB
excludes = [
    "tkinter", "unittest", "test", "pydoc", "doctest",
    "numpy", "pandas", "matplotlib", "scipy", "PIL",
    "PyQt6.QtWebEngineCore", "PyQt6.QtWebEngineWidgets", "PyQt6.QtWebEngineQuick",
    "PyQt6.QtQml", "PyQt6.QtQuick", "PyQt6.QtQuick3D", "PyQt6.Qt3DCore",
    "PyQt6.QtMultimedia", "PyQt6.QtMultimediaWidgets", "PyQt6.QtBluetooth",
    "PyQt6.QtNfc", "PyQt6.QtPositioning", "PyQt6.QtSerialPort",
    "PyQt6.QtCharts", "PyQt6.QtDataVisualization", "PyQt6.QtPdf",
    "PyQt6.QtDesigner", "PyQt6.QtHelp", "PyQt6.QtTest", "PyQt6.QtSql",
]

a = Analysis(
    ["main.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        ("rules", "rules"),                 # กฎ YARA เริ่มต้น
        ("assets/icon.ico", "assets"),      # ไอคอน (ถ้ามี — ไม่มีให้ลบบรรทัดนี้)
    ],
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # ⚠️ อย่าเปิด UPX! อธิบายเหตุผลด้านล่าง
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,             # False = ไม่มีหน้าต่างดำ (โหมดปกติ)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/icon.ico",    # ไม่มีไอคอนให้ลบบรรทัดนี้
    version="versioninfo.txt",
    uac_admin=False,           # True = ขอสิทธิ์ Admin ทุกครั้ง (ยังไม่จำเป็น)
)
