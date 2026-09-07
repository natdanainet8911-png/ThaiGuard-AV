"""หน้าต่างหลักของ ThaiGuard AV"""
import csv
import json
import os
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QAction
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QGridLayout, QLabel,
    QPushButton, QListWidget, QListWidgetItem, QStackedWidget, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar, QFileDialog,
    QMessageBox, QCheckBox, QLineEdit, QTextEdit, QAbstractItemView,
    QSpinBox, QSizePolicy, QComboBox, QSplitter, QInputDialog, QApplication,
)

from config import (APP_NAME, APP_VERSION, DEFAULT_SETTINGS, RISK_HIGH,
                    RISK_MEDIUM, QUARANTINE_DIR, DATA_DIR)
from core.database import Database
from core.scanner import ScanEngine, ScanWorker
from core.yara_engine import YaraEngine
from core.quarantine import QuarantineManager
from core.monitor import RealtimeMonitor
from ui.style import STYLE

COLOR = {
    "MALICIOUS": "#ef4444",
    "SUSPICIOUS": "#f59e0b",
    "CLEAN": "#4ade80",
    "ERROR": "#64748b",
    "SKIPPED": "#64748b",
}
LABEL_TH = {
    "MALICIOUS": "🔴 อันตราย",
    "SUSPICIOUS": "🟡 น่าสงสัย",
    "CLEAN": "🟢 ปลอดภัย",
    "ERROR": "⚪ อ่านไม่ได้",
    "SKIPPED": "⚪ ข้าม",
}


def human_size(n: int) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def make_card(title: str, value: str, color: str):
    card = QFrame(); card.setObjectName("StatCard")
    lay = QVBoxLayout(card); lay.setContentsMargins(16, 14, 16, 14); lay.setSpacing(2)
    v = QLabel(value); v.setObjectName("StatValue"); v.setStyleSheet(f"color:{color};")
    t = QLabel(title); t.setObjectName("StatLabel")
    lay.addWidget(v); lay.addWidget(t)
    return card, v


# ======================================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.yara = YaraEngine()
        self.engine = ScanEngine(self.db, self.yara)
        self.quarantine = QuarantineManager(self.db)
        self.monitor = RealtimeMonitor(self.engine)
        self.worker = None
        self.scan_id = None
        self.results: list[dict] = []

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.resize(1280, 800)
        self.setMinimumSize(1080, 680)
        self.setStyleSheet(STYLE)

        self._build_ui()
        self._connect()
        self._load_settings()
        self.refresh_all()

    # ================================================== UI CONSTRUCTION
    def _build_ui(self):
        root = QWidget(); root.setObjectName("Root")
        self.setCentralWidget(root)
        h = QHBoxLayout(root); h.setContentsMargins(0, 0, 0, 0); h.setSpacing(0)

        # ---------------- Sidebar ----------------
        side = QWidget(); side.setObjectName("Sidebar"); side.setFixedWidth(230)
        sv = QVBoxLayout(side); sv.setContentsMargins(0, 0, 0, 0); sv.setSpacing(0)

        logo = QLabel("🛡️  ThaiGuard"); logo.setObjectName("Logo")
        sub = QLabel(f"Antivirus Scanner v{APP_VERSION}"); sub.setObjectName("LogoSub")
        sv.addWidget(logo); sv.addWidget(sub)

        self.nav = QListWidget(); self.nav.setObjectName("Nav")
        for icon, text in [("🔍", "  สแกนไวรัส"), ("🔒", "  ไฟล์กักกัน"),
                           ("📊", "  ประวัติการสแกน"), ("🗄️", "  ฐานข้อมูลลายเซ็น"),
                           ("⚙️", "  ตั้งค่า / เกี่ยวกับ")]:
            self.nav.addItem(QListWidgetItem(icon + text))
        self.nav.setCurrentRow(0)
        sv.addWidget(self.nav)
        sv.addStretch()

        self.side_status = QLabel("● ระบบพร้อมใช้งาน")
        self.side_status.setStyleSheet("color:#4ade80; padding:14px 18px; font-size:12px;")
        sv.addWidget(self.side_status)

        # ---------------- Pages ----------------
        self.stack = QStackedWidget()
        self.stack.addWidget(self._page_scan())
        self.stack.addWidget(self._page_quarantine())
        self.stack.addWidget(self._page_history())
        self.stack.addWidget(self._page_signatures())
        self.stack.addWidget(self._page_settings())

        h.addWidget(side)
        h.addWidget(self.stack, 1)

        self.statusBar().showMessage("พร้อมใช้งาน")

    # ------------------------------------------------------- PAGE 1
    def _page_scan(self):
        page = QWidget(); v = QVBoxLayout(page)
        v.setContentsMargins(26, 24, 26, 20); v.setSpacing(16)

        title = QLabel("สแกนหามัลแวร์"); title.setObjectName("PageTitle")
        desc = QLabel("ตรวจสอบไฟล์ด้วย 3 เอนจิน: ลายเซ็น (Signature) • กฎ YARA • ฮิวริสติก")
        desc.setObjectName("PageDesc")
        v.addWidget(title); v.addWidget(desc)

        # --- แถวสถิติ ---
        stats = QHBoxLayout(); stats.setSpacing(12)
        self.card_total, self.lbl_total = make_card("ไฟล์ที่สแกน", "0", "#e2e8f0")
        self.card_threat, self.lbl_threat = make_card("ภัยคุกคาม", "0", "#ef4444")
        self.card_susp, self.lbl_susp = make_card("น่าสงสัย", "0", "#f59e0b")
        self.card_clean, self.lbl_clean = make_card("ปลอดภัย", "0", "#4ade80")
        self.card_time, self.lbl_time = make_card("เวลาที่ใช้ (วินาที)", "0.0", "#38bdf8")
        for c in (self.card_total, self.card_threat, self.card_susp,
                  self.card_clean, self.card_time):
            stats.addWidget(c)
        v.addLayout(stats)

        # --- แถบควบคุม ---
        ctrl = QFrame(); ctrl.setObjectName("Card")
        cl = QVBoxLayout(ctrl); cl.setContentsMargins(18, 16, 18, 16); cl.setSpacing(12)

        row1 = QHBoxLayout(); row1.setSpacing(9)
        self.btn_quick = QPushButton("⚡ สแกนด่วน")
        self.btn_quick.setToolTip("สแกน Downloads, Desktop และโฟลเดอร์ชั่วคราว")
        self.btn_file = QPushButton("📄 เลือกไฟล์")
        self.btn_folder = QPushButton("📁 เลือกโฟลเดอร์")
        self.btn_start = QPushButton("▶  เริ่มสแกน"); self.btn_start.setObjectName("Primary")
        self.btn_pause = QPushButton("⏸  หยุดชั่วคราว"); self.btn_pause.setEnabled(False)
        self.btn_stop = QPushButton("⏹  ยกเลิก"); self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        for b in (self.btn_quick, self.btn_file, self.btn_folder):
            row1.addWidget(b)
        row1.addStretch()
        for b in (self.btn_start, self.btn_pause, self.btn_stop):
            row1.addWidget(b)
        cl.addLayout(row1)

        self.lbl_target = QLabel("เป้าหมาย: ยังไม่ได้เลือก")
        self.lbl_target.setStyleSheet("color:#64748b; font-size:12px;")
        cl.addWidget(self.lbl_target)

        self.progress = QProgressBar(); self.progress.setValue(0)
        cl.addWidget(self.progress)

        self.lbl_current = QLabel("รอเริ่มการสแกน...")
        self.lbl_current.setStyleSheet("color:#64748b; font-size:11.5px;")
        cl.addWidget(self.lbl_current)
        v.addWidget(ctrl)

        # --- ตารางผล + รายละเอียด ---
        split = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["ชื่อไฟล์", "ผลตรวจ", "คะแนนเสี่ยง", "ชื่อภัยคุกคาม", "ขนาด", "ตำแหน่งไฟล์"])
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 230); self.table.setColumnWidth(1, 105)
        self.table.setColumnWidth(2, 95);  self.table.setColumnWidth(3, 210)
        self.table.setColumnWidth(4, 85)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        split.addWidget(self.table)

        det = QWidget(); dv = QVBoxLayout(det); dv.setContentsMargins(0, 8, 0, 0)
        drow = QHBoxLayout()
        drow.addWidget(QLabel("รายละเอียดการตรวจจับ"), 0)
        drow.addStretch()
        self.chk_show_clean = QCheckBox("แสดงไฟล์ที่ปลอดภัยด้วย")
        self.btn_quar = QPushButton("🔒 กักกันที่เลือก"); self.btn_quar.setObjectName("Warn")
        self.btn_quar_all = QPushButton("🔒 กักกันทั้งหมดที่เป็นภัย")
        self.btn_export = QPushButton("💾 บันทึกรายงาน CSV")
        for w in (self.chk_show_clean, self.btn_quar, self.btn_quar_all, self.btn_export):
            drow.addWidget(w)
        dv.addLayout(drow)
        self.detail = QTextEdit(); self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("เลือกแถวในตารางเพื่อดูเหตุผลที่ระบบตรวจจับ")
        dv.addWidget(self.detail)
        split.addWidget(det)
        split.setSizes([420, 210])
        v.addWidget(split, 1)

        self.scan_targets: list[str] = []
        return page

    # ------------------------------------------------------- PAGE 2
    def _page_quarantine(self):
        page = QWidget(); v = QVBoxLayout(page)
        v.setContentsMargins(26, 24, 26, 20); v.setSpacing(14)

        t = QLabel("ไฟล์ที่ถูกกักกัน"); t.setObjectName("PageTitle")
        d = QLabel("ไฟล์เหล่านี้ถูกเข้ารหัสและเปลี่ยนนามสกุลแล้ว จึงไม่สามารถทำงานได้")
        d.setObjectName("PageDesc")
        v.addWidget(t); v.addWidget(d)

        row = QHBoxLayout()
        self.btn_q_restore = QPushButton("↩️  กู้คืนไฟล์")
        self.btn_q_delete = QPushButton("🗑️  ลบถาวร"); self.btn_q_delete.setObjectName("Danger")
        self.btn_q_empty = QPushButton("🧹 ล้างทั้งหมด")
        self.btn_q_open = QPushButton("📂 เปิดโฟลเดอร์กักกัน")
        self.btn_q_refresh = QPushButton("🔄 รีเฟรช")
        for b in (self.btn_q_restore, self.btn_q_delete, self.btn_q_empty,
                  self.btn_q_open, self.btn_q_refresh):
            row.addWidget(b)
        row.addStretch()
        v.addLayout(row)

        self.q_table = QTableWidget(0, 6)
        self.q_table.setHorizontalHeaderLabels(
            ["ID", "ชื่อไฟล์เดิม", "ภัยคุกคามที่พบ", "คะแนน", "ขนาด", "วันเวลาที่กักกัน"])
        self.q_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.q_table.setColumnWidth(0, 55); self.q_table.setColumnWidth(2, 220)
        self.q_table.setColumnWidth(3, 75); self.q_table.setColumnWidth(4, 90)
        self.q_table.setColumnWidth(5, 160)
        self.q_table.setAlternatingRowColors(True)
        self.q_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.q_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.q_table.verticalHeader().setVisible(False)
        v.addWidget(self.q_table, 1)
        return page

    # ------------------------------------------------------- PAGE 3
    def _page_history(self):
        page = QWidget(); v = QVBoxLayout(page)
        v.setContentsMargins(26, 24, 26, 20); v.setSpacing(14)

        t = QLabel("ประวัติการสแกน"); t.setObjectName("PageTitle")
        d = QLabel("บันทึกทุกครั้งที่สแกน พร้อมรายการภัยคุกคามที่พบ"); d.setObjectName("PageDesc")
        v.addWidget(t); v.addWidget(d)

        row = QHBoxLayout()
        self.btn_h_refresh = QPushButton("🔄 รีเฟรช")
        self.btn_h_clear = QPushButton("🗑️ ล้างประวัติ"); self.btn_h_clear.setObjectName("Danger")
        row.addWidget(self.btn_h_refresh); row.addWidget(self.btn_h_clear); row.addStretch()
        v.addLayout(row)

        split = QSplitter(Qt.Orientation.Vertical)
        self.h_table = QTableWidget(0, 8)
        self.h_table.setHorizontalHeaderLabels(
            ["ID", "เป้าหมาย", "ประเภท", "เริ่มเมื่อ", "ไฟล์", "ภัยคุกคาม", "น่าสงสัย", "เวลา(วิ)"])
        self.h_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.h_table.setColumnWidth(0, 50); self.h_table.setColumnWidth(2, 95)
        self.h_table.setColumnWidth(3, 150)
        self.h_table.setAlternatingRowColors(True)
        self.h_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.h_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.h_table.verticalHeader().setVisible(False)
        split.addWidget(self.h_table)

        self.h_detail = QTextEdit(); self.h_detail.setReadOnly(True)
        self.h_detail.setPlaceholderText("เลือกรายการเพื่อดูไฟล์ที่ตรวจพบในรอบนั้น")
        split.addWidget(self.h_detail)
        split.setSizes([380, 260])
        v.addWidget(split, 1)
        return page

    # ------------------------------------------------------- PAGE 4
    def _page_signatures(self):
        page = QWidget(); v = QVBoxLayout(page)
        v.setContentsMargins(26, 24, 26, 20); v.setSpacing(14)

        t = QLabel("ฐานข้อมูลลายเซ็นไวรัส"); t.setObjectName("PageTitle")
        d = QLabel("เพิ่ม/ลบค่าแฮช SHA-256 ของไฟล์อันตราย และจัดการกฎ YARA")
        d.setObjectName("PageDesc")
        v.addWidget(t); v.addWidget(d)

        row = QHBoxLayout(); row.setSpacing(8)
        self.sig_search = QLineEdit(); self.sig_search.setPlaceholderText("🔎 ค้นหาชื่อหรือแฮช...")
        self.btn_sig_add = QPushButton("➕ เพิ่มจากไฟล์")
        self.btn_sig_manual = QPushButton("✍️ เพิ่มด้วยแฮช")
        self.btn_sig_import = QPushButton("📥 นำเข้า CSV")
        self.btn_sig_del = QPushButton("🗑️ ลบ"); self.btn_sig_del.setObjectName("Danger")
        self.btn_yara_reload = QPushButton("🔄 โหลดกฎ YARA ใหม่")
        row.addWidget(self.sig_search, 1)
        for b in (self.btn_sig_add, self.btn_sig_manual, self.btn_sig_import,
                  self.btn_sig_del, self.btn_yara_reload):
            row.addWidget(b)
        v.addLayout(row)

        self.yara_status = QLabel()
        self.yara_status.setStyleSheet("color:#64748b; font-size:12px;")
        v.addWidget(self.yara_status)

        self.sig_table = QTableWidget(0, 4)
        self.sig_table.setHorizontalHeaderLabels(
            ["SHA-256", "ชื่อภัยคุกคาม", "ระดับ", "เพิ่มเมื่อ"])
        self.sig_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.sig_table.setColumnWidth(1, 280); self.sig_table.setColumnWidth(2, 70)
        self.sig_table.setColumnWidth(3, 150)
        self.sig_table.setAlternatingRowColors(True)
        self.sig_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.sig_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.sig_table.verticalHeader().setVisible(False)
        v.addWidget(self.sig_table, 1)
        return page

    # ------------------------------------------------------- PAGE 5
    def _page_settings(self):
        page = QWidget(); v = QVBoxLayout(page)
        v.setContentsMargins(26, 24, 26, 20); v.setSpacing(16)

        t = QLabel("ตั้งค่าและข้อมูลโปรแกรม"); t.setObjectName("PageTitle")
        v.addWidget(t)

        # --- Real-time ---
        rt = QFrame(); rt.setObjectName("Card")
        rl = QVBoxLayout(rt); rl.setContentsMargins(18, 16, 18, 16); rl.setSpacing(10)
        lab = QLabel("🛡️  การป้องกันแบบเรียลไทม์"); lab.setObjectName("Section")
        rl.addWidget(lab)
        rl.addWidget(QLabel("เฝ้าดูโฟลเดอร์ที่กำหนด และสแกนทันทีเมื่อมีไฟล์ใหม่เข้ามา"))

        r1 = QHBoxLayout()
        self.rt_path = QLineEdit(DEFAULT_SETTINGS["realtime_folder"])
        self.btn_rt_browse = QPushButton("เลือกโฟลเดอร์")
        self.btn_rt_toggle = QPushButton("เปิดการป้องกัน"); self.btn_rt_toggle.setObjectName("Primary")
        r1.addWidget(self.rt_path, 1); r1.addWidget(self.btn_rt_browse); r1.addWidget(self.btn_rt_toggle)
        rl.addLayout(r1)
        self.rt_log = QTextEdit(); self.rt_log.setReadOnly(True); self.rt_log.setMaximumHeight(130)
        rl.addWidget(self.rt_log)
        v.addWidget(rt)

        # --- ตัวเลือกสแกน ---
        so = QFrame(); so.setObjectName("Card")
        sl = QGridLayout(so); sl.setContentsMargins(18, 16, 18, 16); sl.setSpacing(12)
        lab2 = QLabel("⚙️  ตัวเลือกการสแกน"); lab2.setObjectName("Section")
        sl.addWidget(lab2, 0, 0, 1, 2)

        self.opt_auto_quar = QCheckBox("กักกันไฟล์อันตรายโดยอัตโนมัติเมื่อสแกนเสร็จ")
        sl.addWidget(self.opt_auto_quar, 1, 0, 1, 2)

        sl.addWidget(QLabel("ขนาดไฟล์สูงสุดที่จะสแกน (MB):"), 2, 0)
        self.opt_maxsize = QSpinBox(); self.opt_maxsize.setRange(1, 4096)
        self.opt_maxsize.setValue(DEFAULT_SETTINGS["max_file_size_mb"])
        self.opt_maxsize.setFixedWidth(120)
        sl.addWidget(self.opt_maxsize, 2, 1, alignment=Qt.AlignmentFlag.AlignLeft)

        sl.addWidget(QLabel("เกณฑ์ตัดสิน 'อันตราย' (คะแนน):"), 3, 0)
        self.opt_high = QSpinBox(); self.opt_high.setRange(30, 100); self.opt_high.setValue(RISK_HIGH)
        self.opt_high.setFixedWidth(120)
        sl.addWidget(self.opt_high, 3, 1, alignment=Qt.AlignmentFlag.AlignLeft)

        self.btn_save_settings = QPushButton("💾 บันทึกการตั้งค่า")
        self.btn_save_settings.setObjectName("Primary")
        sl.addWidget(self.btn_save_settings, 4, 0, alignment=Qt.AlignmentFlag.AlignLeft)
        v.addWidget(so)

        # --- About ---
        ab = QFrame(); ab.setObjectName("Card")
        al = QVBoxLayout(ab); al.setContentsMargins(18, 16, 18, 16)
        about = QLabel(
            f"<b style='color:#4ade80;font-size:15px'>{APP_NAME} v{APP_VERSION}</b><br><br>"
            "<span style='color:#94a3b8'>"
            "โครงงานพัฒนาเครื่องมือ (Tools Development)<br>"
            "เครื่องมือตรวจจับไฟล์มัลแวร์ด้วยเทคนิค Signature-based, Rule-based (YARA) "
            "และ Heuristic Analysis<br><br>"
            "<b style='color:#f59e0b'>⚠️ ข้อจำกัดที่ควรทราบ</b><br>"
            "• เป็นเครื่องมือเพื่อการศึกษา ไม่สามารถทดแทนโปรแกรมป้องกันไวรัสเชิงพาณิชย์ได้<br>"
            "• ไม่มีการป้องกันระดับ Kernel และไม่มีระบบ Sandbox<br>"
            "• ฐานข้อมูลลายเซ็นมีขนาดเล็กมากเมื่อเทียบกับ AV จริง<br>"
            "• ผลตรวจ 'น่าสงสัย' อาจเป็น False Positive — โปรดตรวจสอบก่อนลบไฟล์<br><br>"
            "ทดสอบด้วยไฟล์มาตรฐาน EICAR เท่านั้น ห้ามใช้มัลแวร์จริง"
            "</span>")
        about.setWordWrap(True)
        al.addWidget(about)
        v.addWidget(ab)
        v.addStretch()
        return page

    # =========================================================== SIGNALS
    def _connect(self):
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)

        # scan page
        self.btn_quick.clicked.connect(self.pick_quick)
        self.btn_file.clicked.connect(self.pick_files)
        self.btn_folder.clicked.connect(self.pick_folder)
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_pause.clicked.connect(self.pause_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.table.itemSelectionChanged.connect(self.show_detail)
        self.btn_quar.clicked.connect(self.quarantine_selected)
        self.btn_quar_all.clicked.connect(self.quarantine_all)
        self.btn_export.clicked.connect(self.export_csv)

        # quarantine page
        self.btn_q_restore.clicked.connect(self.restore_selected)
        self.btn_q_delete.clicked.connect(self.delete_quarantine)
        self.btn_q_empty.clicked.connect(self.empty_quarantine)
        self.btn_q_open.clicked.connect(
            lambda: self._open_folder(QUARANTINE_DIR))
        self.btn_q_refresh.clicked.connect(self.refresh_quarantine)

        # history page
        self.btn_h_refresh.clicked.connect(self.refresh_history)
        self.btn_h_clear.clicked.connect(self.clear_history)
        self.h_table.itemSelectionChanged.connect(self.show_history_detail)

        # signature page
        self.sig_search.textChanged.connect(self.refresh_signatures)
        self.btn_sig_add.clicked.connect(self.add_signature_from_file)
        self.btn_sig_manual.clicked.connect(self.add_signature_manual)
        self.btn_sig_import.clicked.connect(self.import_signatures_csv)
        self.btn_sig_del.clicked.connect(self.delete_signature)
        self.btn_yara_reload.clicked.connect(self.reload_yara)

        # settings
        self.btn_rt_browse.clicked.connect(self.browse_rt_folder)
        self.btn_rt_toggle.clicked.connect(self.toggle_realtime)
        self.btn_save_settings.clicked.connect(self.save_settings)
        self.monitor.detected.connect(self.on_realtime_detect)
        self.monitor.status.connect(lambda m: self.rt_log.append(
            f"[{datetime.now():%H:%M:%S}] {m}"))

    # ============================================================ HELPERS
    def _open_folder(self, path):
        p = str(path)
        try:
            if os.name == "nt":
                os.startfile(p)
            elif os.uname().sysname == "Darwin":
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}"')
        except Exception as e:
            QMessageBox.warning(self, "เปิดโฟลเดอร์ไม่ได้", str(e))

    def refresh_all(self):
        self.refresh_quarantine()
        self.refresh_history()
        self.refresh_signatures()
        self.update_yara_status()

    def update_yara_status(self):
        if self.yara.available():
            self.yara_status.setText(
                f"✅ YARA พร้อมใช้งาน ({self.yara.backend}) — โหลดกฎแล้ว {self.yara.rule_count} ข้อ")
            self.yara_status.setStyleSheet("color:#4ade80; font-size:12px;")
        else:
            self.yara_status.setText(f"⚠️ YARA ใช้งานไม่ได้: {self.yara.error}")
            self.yara_status.setStyleSheet("color:#f59e0b; font-size:12px;")

    # ============================================================ SCANNING
    def pick_quick(self):
        home = Path.home()
        cands = [home / "Downloads", home / "Desktop", home / "Documents",
                 Path(os.environ.get("TEMP", "/tmp"))]
        self.scan_targets = [str(c) for c in cands if c.exists()]
        self.lbl_target.setText(
            f"เป้าหมาย: สแกนด่วน ({len(self.scan_targets)} โฟลเดอร์) — "
            + ", ".join(Path(t).name for t in self.scan_targets))

    def pick_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "เลือกไฟล์ที่ต้องการสแกน")
        if files:
            self.scan_targets = files
            self.lbl_target.setText(f"เป้าหมาย: {len(files)} ไฟล์ที่เลือก")

    def pick_folder(self):
        d = QFileDialog.getExistingDirectory(self, "เลือกโฟลเดอร์ที่ต้องการสแกน")
        if d:
            self.scan_targets = [d]
            self.lbl_target.setText(f"เป้าหมาย: {d}")

    def start_scan(self):
        if not self.scan_targets:
            QMessageBox.information(self, "ยังไม่ได้เลือกเป้าหมาย",
                                    "กรุณาเลือกไฟล์หรือโฟลเดอร์ก่อนเริ่มสแกน")
            return
        if self.worker and self.worker.isRunning():
            return

        self.table.setRowCount(0)
        self.results.clear()
        self.detail.clear()
        for lbl in (self.lbl_total, self.lbl_threat, self.lbl_susp, self.lbl_clean):
            lbl.setText("0")
        self.lbl_time.setText("0.0")
        self.progress.setValue(0)

        stype = "file" if Path(self.scan_targets[0]).is_file() else "folder"
        self.scan_id = self.db.start_scan(
            "; ".join(self.scan_targets[:3]) +
            (f" (+{len(self.scan_targets)-3})" if len(self.scan_targets) > 3 else ""), stype)

        self.worker = ScanWorker(self.engine, self.scan_targets, self.scan_id,
                                 emit_clean=self.chk_show_clean.isChecked())
        self.worker.counting.connect(lambda n: self.lbl_current.setText(f"พบไฟล์ {n:,} รายการ..."))
        self.worker.progress.connect(self.on_progress)
        self.worker.result.connect(self.on_result)
        self.worker.finished_s.connect(self.on_finished)
        self.worker.message.connect(self.statusBar().showMessage)

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_pause.setEnabled(True)
        self.side_status.setText("● กำลังสแกน...")
        self.side_status.setStyleSheet("color:#f59e0b; padding:14px 18px; font-size:12px;")
        self.worker.start()

    def pause_scan(self):
        if self.worker:
            paused = self.worker.toggle_pause()
            self.btn_pause.setText("▶  ทำต่อ" if paused else "⏸  หยุดชั่วคราว")

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.statusBar().showMessage("กำลังยกเลิกการสแกน...")

    def on_progress(self, done, total, path):
        if total:
            self.progress.setMaximum(total)
            self.progress.setValue(done)
            self.progress.setFormat(f"{done:,} / {total:,}  ({done*100//total}%)")
        name = Path(path).name
        self.lbl_current.setText(f"กำลังตรวจสอบ: {name[:70]}")
        self.lbl_total.setText(f"{done:,}")

    def on_result(self, r: dict):
        self.results.append(r)
        row = self.table.rowCount()
        self.table.insertRow(row)

        color = QColor(COLOR.get(r["verdict"], "#94a3b8"))
        cells = [
            r["name"], LABEL_TH.get(r["verdict"], r["verdict"]),
            f"{r['risk_score']:.0f}", r.get("detection", "-"),
            human_size(r["size"]), r["path"],
        ]
        for c, text in enumerate(cells):
            item = QTableWidgetItem(str(text))
            if c in (1, 2):
                item.setForeground(color)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                f = item.font(); f.setBold(True); item.setFont(f)
            if c == 0:
                item.setData(Qt.ItemDataRole.UserRole, len(self.results) - 1)
            self.table.setItem(row, c, item)

        # อัปเดตตัวเลขสรุปแบบสด
        n_threat = sum(1 for x in self.results if x["verdict"] == "MALICIOUS")
        n_susp = sum(1 for x in self.results if x["verdict"] == "SUSPICIOUS")
        self.lbl_threat.setText(str(n_threat))
        self.lbl_susp.setText(str(n_susp))

        if r["verdict"] == "MALICIOUS":
            self.table.scrollToBottom()

    def on_finished(self, s: dict):
        self.db.finish_scan(self.scan_id, s)
        self.progress.setValue(self.progress.maximum())
        self.lbl_total.setText(f"{s['total']:,}")
        self.lbl_threat.setText(str(s["threats"]))
        self.lbl_susp.setText(str(s["suspicious"]))
        self.lbl_clean.setText(f"{s['clean']:,}")
        self.lbl_time.setText(f"{s['duration']:.1f}")

        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_pause.setEnabled(False)
        self.btn_pause.setText("⏸  หยุดชั่วคราว")
        self.side_status.setText("● ระบบพร้อมใช้งาน")
        self.side_status.setStyleSheet("color:#4ade80; padding:14px 18px; font-size:12px;")

        verb = "ยกเลิกการสแกน" if s.get("stopped") else "สแกนเสร็จสิ้น"
        msg = (f"{verb} — ตรวจสอบ {s['total']:,} ไฟล์ ใน {s['duration']:.1f} วินาที | "
               f"อันตราย {s['threats']} | น่าสงสัย {s['suspicious']} | "
               f"อ่านไม่ได้ {s['errors']}")
        self.lbl_current.setText(msg)
        self.statusBar().showMessage(msg)
        self.refresh_history()

        if self.opt_auto_quar.isChecked() and s["threats"]:
            self.quarantine_all(silent=True)

        if s["threats"]:
            QMessageBox.warning(self, "พบภัยคุกคาม",
                f"⚠️ พบไฟล์อันตราย {s['threats']} รายการ\n"
                f"และไฟล์น่าสงสัยอีก {s['suspicious']} รายการ\n\n"
                "แนะนำให้กดปุ่ม 'กักกันทั้งหมดที่เป็นภัย'")
        elif not s.get("stopped"):
            QMessageBox.information(self, "สแกนเสร็จสิ้น",
                f"✅ ไม่พบภัยคุกคาม\nตรวจสอบทั้งหมด {s['total']:,} ไฟล์")

    def show_detail(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        idx = self.table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        if idx is None or idx >= len(self.results):
            return
        r = self.results[idx]
        eng = r.get("engines", {})
        lines = [
            f"📄 ไฟล์          : {r['name']}",
            f"📁 ตำแหน่ง        : {r['path']}",
            f"📏 ขนาด          : {human_size(r['size'])}",
            f"🔑 SHA-256       : {r.get('sha256','-')}",
            f"🔑 MD5           : {r.get('md5','-')}",
            f"📊 เอนโทรปี       : {r.get('entropy',0):.3f} / 8.000",
            "",
            f"⚖️  คะแนนความเสี่ยงรวม : {r['risk_score']:.1f} / 100  →  {LABEL_TH.get(r['verdict'])}",
            f"🏷️  ชื่อภัยคุกคาม      : {r.get('detection','-')}",
            "",
            "── คะแนนแยกตามเอนจิน ─────────────────────────",
            f"  • Signature (ลายเซ็น)  : {eng.get('signature',{}).get('score',0)}",
            f"  • YARA (กฎ)           : {eng.get('yara',{}).get('score',0)}",
            f"  • Heuristic (ฮิวริสติก) : {eng.get('heuristic',{}).get('score',0)}",
            "",
            "── เหตุผลที่ตรวจจับ ──────────────────────────",
        ]
        reasons = r.get("reasons", [])
        lines += [f"  {i}. {x}" for i, x in enumerate(reasons, 1)] if reasons \
            else ["  ไม่พบสิ่งผิดปกติ"]
        self.detail.setPlainText("\n".join(lines))

    # ------------------------------------------------------- quarantine
    def _selected_results(self):
        out = []
        for r in self.table.selectionModel().selectedRows():
            idx = self.table.item(r.row(), 0).data(Qt.ItemDataRole.UserRole)
            if idx is not None and idx < len(self.results):
                out.append(self.results[idx])
        return out

    def quarantine_selected(self):
        items = self._selected_results()
        if not items:
            QMessageBox.information(self, "ยังไม่ได้เลือก", "กรุณาเลือกไฟล์ในตารางก่อน")
            return
        self._do_quarantine(items)

    def quarantine_all(self, silent=False):
        items = [r for r in self.results if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]
        if not items:
            if not silent:
                QMessageBox.information(self, "ไม่มีรายการ", "ไม่พบไฟล์ที่ต้องกักกัน")
            return
        if not silent:
            ok = QMessageBox.question(
                self, "ยืนยันการกักกัน",
                f"ต้องการกักกันไฟล์ {len(items)} รายการหรือไม่?\n\n"
                "ไฟล์จะถูกย้ายไปโฟลเดอร์กักกันและเข้ารหัส (กู้คืนได้ภายหลัง)")
            if ok != QMessageBox.StandardButton.Yes:
                return
        self._do_quarantine(items)

    def _do_quarantine(self, items):
        ok_n, fail = 0, []
        for r in items:
            success, msg = self.quarantine.quarantine(r)
            if success:
                ok_n += 1
            else:
                fail.append(f"{r['name']}: {msg}")
        self.refresh_quarantine()
        text = f"กักกันสำเร็จ {ok_n} ไฟล์"
        if fail:
            text += f"\n\nไม่สำเร็จ {len(fail)} ไฟล์:\n" + "\n".join(fail[:6])
        QMessageBox.information(self, "ผลการกักกัน", text)
        self.statusBar().showMessage(f"กักกันแล้ว {ok_n} ไฟล์")

    def refresh_quarantine(self):
        rows = self.db.list_quarantine()
        self.q_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            vals = [str(r["id"]), r["original_path"], r["detection"],
                    f"{r['risk_score']:.0f}", human_size(r["size"] or 0),
                    r["quarantined_at"]]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c in (0, 3):
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if c == 2:
                    it.setForeground(QColor("#f59e0b"))
                self.q_table.setItem(i, c, it)

    def _selected_qid(self):
        rows = self.q_table.selectionModel().selectedRows()
        return int(self.q_table.item(rows[0].row(), 0).text()) if rows else None

    def restore_selected(self):
        qid = self._selected_qid()
        if qid is None:
            QMessageBox.information(self, "ยังไม่ได้เลือก", "กรุณาเลือกรายการที่ต้องการกู้คืน")
            return
        rec = self.db.get_quarantine(qid)
        ok = QMessageBox.warning(
            self, "⚠️ ยืนยันการกู้คืน",
            f"ไฟล์นี้ถูกตรวจพบว่า: {rec['detection']}\n"
            f"คะแนนความเสี่ยง: {rec['risk_score']:.0f}/100\n\n"
            "การกู้คืนจะนำไฟล์กลับสู่สภาพเดิมและอาจเป็นอันตราย\nยืนยันหรือไม่?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if ok != QMessageBox.StandardButton.Yes:
            return
        success, msg = self.quarantine.restore(qid)
        QMessageBox.information(self, "ผลการกู้คืน", msg)
        self.refresh_quarantine()

    def delete_quarantine(self):
        qid = self._selected_qid()
        if qid is None:
            return
        if QMessageBox.question(self, "ยืนยัน", "ลบไฟล์นี้อย่างถาวร? (กู้คืนไม่ได้)") \
                != QMessageBox.StandardButton.Yes:
            return
        _, msg = self.quarantine.delete_permanently(qid)
        self.refresh_quarantine()
        self.statusBar().showMessage(msg)

    def empty_quarantine(self):
        if QMessageBox.question(self, "ยืนยัน",
                                "ลบไฟล์กักกันทั้งหมดอย่างถาวร?") \
                != QMessageBox.StandardButton.Yes:
            return
        n = self.quarantine.empty_all()
        self.refresh_quarantine()
        QMessageBox.information(self, "เสร็จสิ้น", f"ลบไปทั้งหมด {n} ไฟล์")

    # ---------------------------------------------------------- history
    def refresh_history(self):
        rows = self.db.list_scans()
        self.h_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            vals = [str(r["id"]), r["target"] or "-", r["scan_type"] or "-",
                    r["started_at"] or "-", f"{r['total_files']:,}",
                    str(r["threats"]), str(r["suspicious"]), f"{r['duration']:.1f}"]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c != 1:
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if c == 5 and r["threats"]:
                    it.setForeground(QColor("#ef4444"))
                if c == 6 and r["suspicious"]:
                    it.setForeground(QColor("#f59e0b"))
                self.h_table.setItem(i, c, it)

    def show_history_detail(self):
        rows = self.h_table.selectionModel().selectedRows()
        if not rows:
            return
        sid = int(self.h_table.item(rows[0].row(), 0).text())
        dets = self.db.list_detections(sid)
        if not dets:
            self.h_detail.setPlainText("รอบการสแกนนี้ไม่พบไฟล์ที่เป็นภัยคุกคาม ✅")
            return
        out = [f"พบทั้งหมด {len(dets)} รายการ", "=" * 68]
        for d in dets:
            try:
                reasons = json.loads(d["reasons"])
            except Exception:
                reasons = []
            out += [
                f"\n[{d['verdict']}]  {d['filename']}   (คะแนน {d['risk_score']:.0f})",
                f"  ตำแหน่ง : {d['filepath']}",
                f"  ตรวจพบ : {d['detection']}",
                f"  SHA-256: {d['sha256'][:48]}...",
            ]
            out += [f"    • {x}" for x in reasons[:4]]
        self.h_detail.setPlainText("\n".join(out))

    def clear_history(self):
        if QMessageBox.question(self, "ยืนยัน", "ล้างประวัติการสแกนทั้งหมด?") \
                == QMessageBox.StandardButton.Yes:
            self.db.clear_history()
            self.refresh_history()
            self.h_detail.clear()

    # ------------------------------------------------------- signatures
    def refresh_signatures(self):
        rows = self.db.list_signatures(self.sig_search.text().strip())
        self.sig_table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            for c, v in enumerate([r["sha256"], r["name"], str(r["severity"]),
                                   r["added_at"] or "-"]):
                it = QTableWidgetItem(v)
                if c == 0:
                    it.setFont(QFont("Consolas", 9))
                if c in (2, 3):
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.sig_table.setItem(i, c, it)
        self.statusBar().showMessage(f"ฐานข้อมูลมี {self.db.signature_count():,} ลายเซ็น")

    def add_signature_from_file(self):
        f, _ = QFileDialog.getOpenFileName(self, "เลือกไฟล์ตัวอย่างเพื่อสร้างลายเซ็น")
        if not f:
            return
        from core.hasher import hash_file
        try:
            h = hash_file(f)
        except Exception as e:
            QMessageBox.warning(self, "ผิดพลาด", str(e)); return
        name, ok = QInputDialog.getText(self, "ตั้งชื่อภัยคุกคาม", "ชื่อ:",
                                        text=f"Custom.{Path(f).stem}")
        if ok and name:
            self.db.add_signature(h["sha256"], name)
            self.refresh_signatures()
            QMessageBox.information(self, "เพิ่มสำเร็จ",
                                    f"เพิ่มลายเซ็นแล้ว\nSHA-256: {h['sha256']}")

    def add_signature_manual(self):
        sha, ok = QInputDialog.getText(self, "เพิ่มลายเซ็น", "ค่าแฮช SHA-256 (64 ตัวอักษร):")
        if not ok or not sha:
            return
        sha = sha.strip().lower()
        if len(sha) != 64:
            QMessageBox.warning(self, "รูปแบบไม่ถูกต้อง", "SHA-256 ต้องมี 64 ตัวอักษร")
            return
        name, ok2 = QInputDialog.getText(self, "ตั้งชื่อภัยคุกคาม", "ชื่อ:")
        if ok2 and name:
            self.db.add_signature(sha, name)
            self.refresh_signatures()

    def import_signatures_csv(self):
        f, _ = QFileDialog.getOpenFileName(self, "เลือกไฟล์ CSV (คอลัมน์: sha256,name)",
                                           filter="CSV (*.csv)")
        if not f:
            return
        n = 0
        try:
            with open(f, newline="", encoding="utf-8-sig") as fh:
                for row in csv.reader(fh):
                    if len(row) >= 2 and len(row[0].strip()) == 64:
                        self.db.add_signature(row[0].strip(), row[1].strip(), source="import")
                        n += 1
        except Exception as e:
            QMessageBox.warning(self, "นำเข้าไม่สำเร็จ", str(e)); return
        self.refresh_signatures()
        QMessageBox.information(self, "นำเข้าสำเร็จ", f"เพิ่มลายเซ็น {n} รายการ")

    def delete_signature(self):
        rows = self.sig_table.selectionModel().selectedRows()
        if not rows:
            return
        for r in rows:
            self.db.delete_signature(self.sig_table.item(r.row(), 0).text())
        self.refresh_signatures()

    def reload_yara(self):
        self.yara.reload()
        self.update_yara_status()
        QMessageBox.information(self, "โหลดกฎใหม่",
            f"โหลดกฎ YARA สำเร็จ {self.yara.rule_count} ข้อ"
            if self.yara.available() else f"ไม่สำเร็จ: {self.yara.error}")

    # --------------------------------------------------------- realtime
    def browse_rt_folder(self):
        d = QFileDialog.getExistingDirectory(self, "เลือกโฟลเดอร์ที่ต้องการเฝ้าดู")
        if d:
            self.rt_path.setText(d)

    def toggle_realtime(self):
        if self.monitor.observer:
            self.monitor.stop()
            self.btn_rt_toggle.setText("เปิดการป้องกัน")
            self.btn_rt_toggle.setObjectName("Primary")
        else:
            folder = self.rt_path.text().strip()
            if not Path(folder).is_dir():
                QMessageBox.warning(self, "โฟลเดอร์ไม่ถูกต้อง", "กรุณาเลือกโฟลเดอร์ที่มีอยู่จริง")
                return
            if self.monitor.start(folder):
                self.btn_rt_toggle.setText("ปิดการป้องกัน")
                self.btn_rt_toggle.setObjectName("Danger")
        self.btn_rt_toggle.setStyleSheet("")
        self.setStyleSheet(STYLE)   # บังคับรีเฟรช objectName style

    def on_realtime_detect(self, r: dict):
        self.rt_log.append(
            f"[{datetime.now():%H:%M:%S}] ⚠️ ตรวจพบ {r['verdict']} — "
            f"{r['name']} (คะแนน {r['risk_score']:.0f}) : {r.get('detection','-')}")
        QMessageBox.warning(self, "🛡️ การป้องกันเรียลไทม์",
            f"ตรวจพบไฟล์ที่เป็นภัย!\n\n"
            f"ไฟล์: {r['name']}\nตำแหน่ง: {r['path']}\n"
            f"ผลตรวจ: {r.get('detection','-')}\nคะแนนเสี่ยง: {r['risk_score']:.0f}/100")

    # --------------------------------------------------------- settings
    def _load_settings(self):
        self.opt_auto_quar.setChecked(self.db.get_setting("auto_quarantine", False))
        self.opt_maxsize.setValue(self.db.get_setting("max_file_size_mb", 150))
        self.opt_high.setValue(self.db.get_setting("risk_high", RISK_HIGH))
        self.rt_path.setText(self.db.get_setting(
            "realtime_folder", DEFAULT_SETTINGS["realtime_folder"]))
        self.chk_show_clean.setChecked(self.db.get_setting("show_clean_files", False))

    def save_settings(self):
        import config
        self.db.set_setting("auto_quarantine", self.opt_auto_quar.isChecked())
        self.db.set_setting("max_file_size_mb", self.opt_maxsize.value())
        self.db.set_setting("risk_high", self.opt_high.value())
        self.db.set_setting("realtime_folder", self.rt_path.text())
        self.db.set_setting("show_clean_files", self.chk_show_clean.isChecked())

        config.MAX_SCAN_SIZE = self.opt_maxsize.value() * 1024 * 1024
        config.RISK_HIGH = self.opt_high.value()
        QMessageBox.information(self, "บันทึกแล้ว", "บันทึกการตั้งค่าเรียบร้อย ✅")

    # ----------------------------------------------------------- export
    def export_csv(self):
        if not self.results:
            QMessageBox.information(self, "ไม่มีข้อมูล", "ยังไม่มีผลการสแกนให้บันทึก")
            return
        default = f"ThaiGuard_Report_{datetime.now():%Y%m%d_%H%M%S}.csv"
        f, _ = QFileDialog.getSaveFileName(self, "บันทึกรายงาน", default, "CSV (*.csv)")
        if not f:
            return
        try:
            with open(f, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(["ชื่อไฟล์", "ตำแหน่ง", "ขนาด(ไบต์)", "SHA-256",
                            "ผลตรวจ", "คะแนนเสี่ยง", "ชื่อภัยคุกคาม",
                            "เอนโทรปี", "เหตุผล"])
                for r in self.results:
                    w.writerow([r["name"], r["path"], r["size"], r.get("sha256", ""),
                                r["verdict"], r["risk_score"], r.get("detection", ""),
                                r.get("entropy", 0), " | ".join(r.get("reasons", []))])
            QMessageBox.information(self, "บันทึกสำเร็จ", f"บันทึกรายงานไปที่:\n{f}")
        except Exception as e:
            QMessageBox.warning(self, "บันทึกไม่สำเร็จ", str(e))

    # ------------------------------------------------------------ close
    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            if QMessageBox.question(self, "กำลังสแกนอยู่",
                                    "การสแกนยังไม่เสร็จ ต้องการปิดโปรแกรมหรือไม่?") \
                    != QMessageBox.StandardButton.Yes:
                event.ignore(); return
            self.worker.stop()
            self.worker.wait(3000)
        self.monitor.stop()
        self.db.close()
        event.accept()
