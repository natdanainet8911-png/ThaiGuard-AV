"""ธีมมืดแบบ Modern Security Dashboard"""

STYLE = """
* { font-family: 'Segoe UI', 'Noto Sans Thai', 'Leelawadee UI', sans-serif; }

QMainWindow, QWidget#Root { background: #0f1420; }

/* ---------- Sidebar ---------- */
QWidget#Sidebar { background: #151b2b; border-right: 1px solid #232c42; }
QLabel#Logo {
    color: #4ade80; font-size: 20px; font-weight: 700; padding: 22px 18px 4px 18px;
}
QLabel#LogoSub { color: #64748b; font-size: 11px; padding: 0 18px 18px 18px; }

QListWidget#Nav {
    background: transparent; border: none; outline: none;
    color: #94a3b8; font-size: 14px;
}
QListWidget#Nav::item { padding: 13px 18px; border-left: 3px solid transparent; }
QListWidget#Nav::item:hover { background: #1c2434; color: #e2e8f0; }
QListWidget#Nav::item:selected {
    background: #1c2740; color: #4ade80; border-left: 3px solid #4ade80;
    font-weight: 600;
}

/* ---------- Cards ---------- */
QFrame#Card {
    background: #151b2b; border: 1px solid #232c42; border-radius: 12px;
}
QFrame#StatCard {
    background: #151b2b; border: 1px solid #232c42; border-radius: 12px;
    padding: 4px;
}
QLabel#StatValue { font-size: 26px; font-weight: 700; }
QLabel#StatLabel { color: #64748b; font-size: 12px; }
QLabel#PageTitle { color: #f1f5f9; font-size: 22px; font-weight: 700; }
QLabel#PageDesc  { color: #64748b; font-size: 13px; }
QLabel#Section   { color: #cbd5e1; font-size: 14px; font-weight: 600; }

/* ---------- Buttons ---------- */
QPushButton {
    background: #1e293b; color: #e2e8f0; border: 1px solid #334155;
    border-radius: 8px; padding: 9px 18px; font-size: 13px;
}
QPushButton:hover   { background: #273449; border-color: #475569; }
QPushButton:pressed { background: #16202f; }
QPushButton:disabled { color: #475569; background: #161d2b; border-color: #232c42; }

QPushButton#Primary {
    background: #16a34a; border: none; color: #ffffff; font-weight: 600;
    padding: 11px 24px;
}
QPushButton#Primary:hover   { background: #22c55e; }
QPushButton#Primary:pressed { background: #15803d; }

QPushButton#Danger { background: #dc2626; border: none; color: white; }
QPushButton#Danger:hover { background: #ef4444; }

QPushButton#Warn { background: #d97706; border: none; color: white; }
QPushButton#Warn:hover { background: #f59e0b; }

/* ---------- Inputs ---------- */
QLineEdit, QSpinBox, QComboBox {
    background: #0f1420; color: #e2e8f0; border: 1px solid #334155;
    border-radius: 8px; padding: 9px 12px; selection-background-color: #16a34a;
}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border-color: #16a34a; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background: #151b2b; color: #e2e8f0; selection-background-color: #1e3a2f;
    border: 1px solid #334155;
}

/* ---------- Table ---------- */
QTableWidget {
    background: #121826; alternate-background-color: #151b2b;
    color: #cbd5e1; gridline-color: #232c42; border: 1px solid #232c42;
    border-radius: 10px; selection-background-color: #1e3a2f;
    selection-color: #ffffff; font-size: 12.5px;
}
QHeaderView::section {
    background: #1b2436; color: #94a3b8; padding: 10px 8px; border: none;
    border-right: 1px solid #232c42; border-bottom: 1px solid #232c42;
    font-weight: 600; font-size: 12px;
}
QTableWidget::item { padding: 7px 6px; }

/* ---------- Progress ---------- */
QProgressBar {
    background: #0f1420; border: 1px solid #232c42; border-radius: 9px;
    height: 18px; text-align: center; color: #e2e8f0; font-size: 11px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #16a34a, stop:1 #4ade80);
    border-radius: 8px;
}

/* ---------- Misc ---------- */
QCheckBox { color: #cbd5e1; spacing: 9px; font-size: 13px; }
QCheckBox::indicator {
    width: 17px; height: 17px; border-radius: 5px;
    border: 1px solid #475569; background: #0f1420;
}
QCheckBox::indicator:checked { background: #16a34a; border-color: #16a34a; }

QTextEdit {
    background: #0b0f18; color: #94a3b8; border: 1px solid #232c42;
    border-radius: 10px; font-family: 'Consolas','Courier New',monospace;
    font-size: 12px; padding: 8px;
}
QStatusBar { background: #151b2b; color: #64748b; border-top: 1px solid #232c42; }
QScrollBar:vertical { background: #0f1420; width: 11px; margin: 0; }
QScrollBar::handle:vertical { background: #334155; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #475569; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QSplitter::handle { background: #232c42; }
QToolTip {
    background: #1e293b; color: #e2e8f0; border: 1px solid #334155;
    padding: 6px; border-radius: 6px;
}
"""
