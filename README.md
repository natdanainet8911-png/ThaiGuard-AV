<div align="center">

# 🛡️ ThaiGuard AV

**เครื่องมือตรวจจับไฟล์มัลแวร์ด้วยเทคนิค Multi-Engine**
Signature-based · Rule-based (YARA) · Heuristic Analysis

[![Build](https://github.com/USERNAME/thaiguard-av/actions/workflows/build.yml/badge.svg)](https://github.com/USERNAME/thaiguard-av/actions)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![PyQt6](https://img.shields.io/badge/GUI-PyQt6-41CD52?logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[ดาวน์โหลด .exe](../../releases/latest) · [วิธีใช้งาน](#-การใช้งาน) · [รายงานบั๊ก](../../issues)

</div>

---

## ⚠️ ข้อความปฏิเสธความรับผิดชอบ

> โปรแกรมนี้เป็น **โครงงานเพื่อการศึกษา** ไม่สามารถทดแทนโปรแกรมป้องกันไวรัสเชิงพาณิชย์ได้
> ห้ามนำมัลแวร์จริงมาทดสอบ — ให้ใช้ไฟล์มาตรฐาน [EICAR](https://www.eicar.org/download-anti-malware-testfile/) เท่านั้น
> ผู้พัฒนาไม่รับผิดชอบต่อความเสียหายใด ๆ ที่เกิดจากการใช้งาน

---

## ✨ คุณสมบัติ

| ฟีเจอร์ | รายละเอียด |
|---|---|
| 🔍 **Multi-Engine Scan** | รวม 3 เอนจิน คำนวณคะแนนแบบถ่วงน้ำหนัก 45% / 30% / 25% |
| 🧬 **Signature-based** | เทียบค่าแฮช SHA-256 กับฐานข้อมูล SQLite |
| 📜 **YARA Rules** | กฎเริ่มต้น 10 ข้อ เพิ่มเองได้ รองรับทั้ง yara-python และ YARA-X |
| 🧠 **Heuristic** | Shannon Entropy · PE Import Analysis · นามสกุลไฟล์ซ้อน · Pattern matching |
| 🔒 **Quarantine** | เข้ารหัสไฟล์ + เปลี่ยนนามสกุล กู้คืนได้ 100% |
| 🛡️ **Real-time Protection** | เฝ้าโฟลเดอร์แบบเรียลไทม์ด้วย watchdog |
| 📊 **ประวัติ + รายงาน** | บันทึกทุกการสแกน ส่งออก CSV เปิดใน Excel ภาษาไทยไม่เพี้ยน |

## 🖼️ ภาพหน้าจอ

| หน้าสแกน | หน้ากักกัน |
|---|---|
| ![scan](docs/screenshot-scan.png) | ![quarantine](docs/screenshot-quarantine.png) |

## 🚀 ติดตั้งและใช้งาน

### วิธีที่ 1 — ดาวน์โหลด .exe (ง่ายที่สุด)
ไปที่หน้า [Releases](../../releases/latest) แล้วโหลด `ThaiGuardAV.exe`

### วิธีที่ 2 — รันจากซอร์สโค้ด
```bash
git clone https://github.com/USERNAME/thaiguard-av.git
cd thaiguard-av
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
python tools/make_eicar.py     # สร้างไฟล์ทดสอบที่ปลอดภัย
python main.py
```

## 🧪 การทดสอบ

```bash
python tools/make_eicar.py
```
สร้างไฟล์ทดสอบ 4 แบบในโฟลเดอร์ `testfiles/` แล้วใช้โปรแกรมสแกนโฟลเดอร์นั้น

| ไฟล์ทดสอบ | เอนจินที่ควรตรวจเจอ |
|---|---|
| `eicar_test.com` | Signature + YARA |
| `invoice.pdf.exe` | Heuristic (นามสกุลซ้อน) |
| `suspicious_script.ps1` | YARA (PowerShell Downloader) |
| `ransom_sim.txt` | YARA (Ransomware Indicators) |

## 🏗️ สถาปัตยกรรม

```
GUI (PyQt6)
    ↓
ScanWorker (QThread) ──→ ScanEngine
                            ├── Signature Engine (SHA-256 + SQLite)
                            ├── YARA Engine (Rule matching)
                            └── Heuristic Engine (Entropy/PE/Pattern)
                                     ↓
                            Risk Scoring (ถ่วงน้ำหนัก)
                                     ↓
                    Quarantine · SQLite · CSV Report
```

## ❓ Windows Defender เตือนว่าเป็นไวรัส?

เป็นเรื่อง**ปกติและคาดหมายได้** เพราะ:
1. ไฟล์ที่สร้างด้วย PyInstaller ใช้ bootloader ร่วมกัน ซึ่งมัลแวร์จำนวนมากก็ใช้
2. ไฟล์ไม่ได้เซ็นด้วย Code Signing Certificate
3. ตัวโปรแกรมมี**สตริงของกฎ YARA** เช่น `vssadmin delete shadows` ฝังอยู่ภายใน

**วิธีแก้:** ตรวจสอบค่า SHA-256 กับไฟล์ `SHA256SUMS.txt` ก่อน แล้วเพิ่ม exclusion ให้ไฟล์

## 📋 ข้อจำกัดที่ทราบ

- ❌ ไม่มีการป้องกันระดับ Kernel (ไม่มี driver)
- ❌ ไม่มี Sandbox / Dynamic analysis
- ❌ ฐานข้อมูลลายเซ็นมีขนาดเล็กมาก
- ⚠️ ผลตรวจ "น่าสงสัย" มี False Positive ค่อนข้างสูง

## 📄 License
MIT License — ดูรายละเอียดที่ [LICENSE](LICENSE)
