"""Synthetic fixture factory for WP01 PDF intake test suite.

Generates exactly nine preregistered fixtures:
- text_unicode.pdf: Two-page genuine Vietnamese text with exact keywords (OR, NOT, 20-30).
- image_only.pdf: Single-page bitmap PDF without text layer.
- mixed.pdf: Three-page mixed PDF (text+bitmap, image-only, blank/vector-only).
- locked.pdf: Password-encrypted synthetic PDF.
- corrupt.pdf: Malformed/corrupt PDF header/body.
- unsupported.txt: Non-PDF plain text file.
- page_limit.pdf: 201-page blank PDF exceeding default 200-page limit.
- stream_limit.pdf: Compressed PDF with decoded content stream > 2 MiB.
- expected.json: Independent oracle manifest containing expected states and text.
"""

import argparse
import io
import json
import sys
from pathlib import Path

from PIL import Image
from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

ARIAL_PATH = r"C:\Windows\Fonts\arial.ttf"


def register_fonts():
    """Register system Arial font for Vietnamese Unicode support."""
    if Path(ARIAL_PATH).exists():
        try:
            pdfmetrics.registerFont(TTFont("Arial", ARIAL_PATH))
        except Exception:
            pass


def generate_text_unicode(out_dir: Path) -> Path:
    """Generate two genuine text pages with Vietnamese Unicode, OR, NOT, and 20-30."""
    target = out_dir / "text_unicode.pdf"
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(595, 842))  # A4

    font_name = "Arial" if "Arial" in pdfmetrics.getRegisteredFontNames() else "Helvetica"

    # Page 1
    c.setFont(font_name, 14)
    c.drawString(50, 780, "CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM")
    c.drawString(50, 755, "Độc lập - Tự do - Hạnh phúc")
    c.setFont(font_name, 12)
    c.drawString(50, 720, "HỒ SƠ MỜI THẦU MẪU SỐ 01")
    c.drawString(50, 690, "Quy định: Nhà thầu PHẢI hoặc (OR) KHÔNG ĐƯỢC (NOT) vi phạm tiêu chuẩn.")
    c.drawString(50, 665, "Thời hạn xử lý hồ sơ từ 20 đến 30 ngày làm việc.")
    c.showPage()

    # Page 2
    c.setFont(font_name, 14)
    c.drawString(50, 780, "Trang 2: Yêu cầu về năng lực tài chính và kinh nghiệm thực hiện hợp đồng.")
    c.setFont(font_name, 12)
    c.drawString(50, 740, "Giá trị gói thầu nằm trong khung 20-30 tỷ đồng theo dự toán được phê duyệt.")
    c.showPage()

    c.save()
    target.write_bytes(buf.getvalue())
    return target


def generate_image_only(out_dir: Path) -> Path:
    """Generate single-page bitmap PDF without extractable text layer."""
    target = out_dir / "image_only.pdf"
    img = Image.new("RGB", (200, 200), color=(180, 70, 70))
    img_buf = io.BytesIO()
    img.save(img_buf, format="PNG")
    img_buf.seek(0)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(300, 300))
    c.drawImage(ImageReader(img_buf), 50, 50, width=200, height=200)
    c.showPage()
    c.save()

    target.write_bytes(buf.getvalue())
    return target


def generate_mixed(out_dir: Path) -> Path:
    """Generate three-page PDF with mixed, image-only, and vector-only pages."""
    target = out_dir / "mixed.pdf"
    font_name = "Arial" if "Arial" in pdfmetrics.getRegisteredFontNames() else "Helvetica"

    img = Image.new("RGB", (100, 100), color=(60, 140, 60))
    img_buf = io.BytesIO()
    img.save(img_buf, format="PNG")
    img_buf.seek(0)
    img_reader = ImageReader(img_buf)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(400, 600))

    # Page 1: Text + image (MIXED)
    c.setFont(font_name, 12)
    c.drawString(50, 550, "Tài liệu hỗn hợp trang 1 có văn bản và hình ảnh đính kèm.")
    c.drawImage(img_reader, 50, 350, width=100, height=100)
    c.showPage()

    # Page 2: Image only (IMAGE_ONLY)
    c.drawImage(img_reader, 50, 350, width=100, height=100)
    c.showPage()

    # Page 3: Vector rectangle only, no text/image (UNKNOWN)
    c.setLineWidth(2)
    c.rect(50, 350, 200, 150, stroke=1, fill=0)
    c.showPage()

    c.save()
    target.write_bytes(buf.getvalue())
    return target


def generate_locked(out_dir: Path) -> Path:
    """Generate password-encrypted synthetic PDF."""
    target = out_dir / "locked.pdf"
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(300, 300))
    c.drawString(50, 200, "Tài liệu bảo mật đã được khóa bằng mật mã.")
    c.showPage()
    c.save()
    buf.seek(0)

    reader = PdfReader(buf)
    writer = PdfWriter()
    writer.append(reader)
    writer.encrypt(user_password="user_secret", owner_password="owner_secret")

    out_buf = io.BytesIO()
    writer.write(out_buf)
    target.write_bytes(out_buf.getvalue())
    return target


def generate_corrupt(out_dir: Path) -> Path:
    """Generate malformed corrupt PDF payload."""
    target = out_dir / "corrupt.pdf"
    payload = b"%PDF-1.4\n%MALFORMED_HEADER_PAYLOAD\xff\xfe\x00\x01\x02\x03\x04\x05\nInvalid body"
    target.write_bytes(payload)
    return target


def generate_unsupported(out_dir: Path) -> Path:
    """Generate non-PDF plain text file."""
    target = out_dir / "unsupported.txt"
    content = "Tài liệu văn bản thuần UTF-8 không phải định dạng PDF được hỗ trợ bởi hệ thống.\n"
    target.write_text(content, encoding="utf-8")
    return target


def generate_page_limit(out_dir: Path) -> Path:
    """Generate 201-page blank PDF exceeding default 200-page limit."""
    target = out_dir / "page_limit.pdf"
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(100, 100))
    for i in range(201):
        c.drawString(10, 50, f"P{i+1}")
        c.showPage()
    c.save()

    target.write_bytes(buf.getvalue())
    return target


def generate_stream_limit(out_dir: Path) -> Path:
    """Generate small compressed PDF containing >2 MiB decoded content stream."""
    target = out_dir / "stream_limit.pdf"
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.drawString(100, 700, "Stream limit test payload")
    c.showPage()
    c.save()
    buf.seek(0)

    reader = PdfReader(buf)
    writer = PdfWriter()
    writer.append(reader)
    page = writer.pages[0]

    # Create stream with > 2 MiB decoded bytes (2.15 MiB)
    raw_payload = b"BT /F1 12 Tf 100 700 Td (Stream limit test payload) Tj ET\n% " + (b"X" * 2150000) + b"\n"
    stream_obj = DecodedStreamObject()
    stream_obj.set_data(raw_payload)
    encoded_stream = stream_obj.flate_encode()
    page[NameObject("/Contents")] = writer._add_object(encoded_stream)

    out_buf = io.BytesIO()
    writer.write(out_buf)
    target.write_bytes(out_buf.getvalue())
    return target


def generate_expected_oracle(out_dir: Path) -> Path:
    """Generate independent constant oracle manifest for the synthetic fixtures."""
    target = out_dir / "expected.json"
    oracle_data = {
        "oracle_version": "wp01-v1",
        "rule_version": "wp01-v1",
        "parser_version": "pypdf/6.10.0",
        "fixtures": {
            "text_unicode.pdf": {
                "read_state": "TEXT_EXTRACTABLE",
                "page_count": 2,
                "is_valid": True,
                "pages": [
                    {
                        "page_index": 0,
                        "locator": "page-1",
                        "state": "TEXT_EXTRACTABLE",
                        "expected_keywords": ["CỘNG HÒA XÃ HỘI CHỦ NGHĨA VIỆT NAM", "OR", "NOT", "20 đến 30"],
                        "warnings": []
                    },
                    {
                        "page_index": 1,
                        "locator": "page-2",
                        "state": "TEXT_EXTRACTABLE",
                        "expected_keywords": ["20-30 tỷ đồng"],
                        "warnings": []
                    }
                ]
            },
            "image_only.pdf": {
                "read_state": "IMAGE_ONLY",
                "page_count": 1,
                "is_valid": True,
                "pages": [
                    {
                        "page_index": 0,
                        "locator": "page-1",
                        "state": "IMAGE_ONLY",
                        "warnings": ["IMAGE_ONLY_NO_TEXT: page contains bitmap without extractable text layer"]
                    }
                ]
            },
            "mixed.pdf": {
                "read_state": "MIXED",
                "page_count": 3,
                "is_valid": True,
                "pages": [
                    {
                        "page_index": 0,
                        "locator": "page-1",
                        "state": "MIXED",
                        "warnings": ["MIXED_CONTENT: page contains both text and bitmap elements"]
                    },
                    {
                        "page_index": 1,
                        "locator": "page-2",
                        "state": "IMAGE_ONLY",
                        "warnings": ["IMAGE_ONLY_NO_TEXT: page contains bitmap without extractable text layer"]
                    },
                    {
                        "page_index": 2,
                        "locator": "page-3",
                        "state": "UNKNOWN",
                        "warnings": ["UNKNOWN_COVERAGE: page contains vector/blank elements without extractable text or bitmap"]
                    }
                ]
            },
            "locked.pdf": {
                "read_state": "LOCKED",
                "page_count": 0,
                "is_valid": False,
                "warnings": ["LOCKED_DOCUMENT: document is password encrypted; decryption not attempted"]
            },
            "corrupt.pdf": {
                "read_state": "CORRUPT",
                "page_count": 0,
                "is_valid": False,
                "warnings": ["CORRUPT_DOCUMENT: malformed or unreadable PDF payload"]
            },
            "unsupported.txt": {
                "read_state": "UNSUPPORTED",
                "page_count": 0,
                "is_valid": False,
                "warnings": ["UNSUPPORTED_FORMAT: input is not a recognized PDF format"]
            },
            "page_limit.pdf": {
                "read_state": "LIMIT",
                "page_count": 201,
                "is_valid": False,
                "warnings": ["PAGE_LIMIT_EXCEEDED: page count 201 exceeds limit 200"]
            },
            "stream_limit.pdf": {
                "read_state": "LIMIT",
                "page_count": 1,
                "is_valid": False,
                "warnings": ["STREAM_LIMIT_EXCEEDED: decoded content stream exceeds 2097152 bytes"]
            }
        }
    }
    content = json.dumps(oracle_data, indent=2, ensure_ascii=False) + "\n"
    target.write_text(content, encoding="utf-8")
    return target


def build_all_fixtures(out_dir: Path):
    """Build all nine registered fixtures into the target directory."""
    out_dir.mkdir(parents=True, exist_ok=True)
    register_fonts()

    generators = [
        generate_text_unicode,
        generate_image_only,
        generate_mixed,
        generate_locked,
        generate_corrupt,
        generate_unsupported,
        generate_page_limit,
        generate_stream_limit,
        generate_expected_oracle,
    ]

    manifest = []
    for gen in generators:
        created = gen(out_dir)
        manifest.append((created.name, created.stat().st_size))

    return manifest


def main():
    parser = argparse.ArgumentParser(description="Synthetic fixture factory for WP01.")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "fixtures",
        help="Target output directory for fixtures",
    )
    args = parser.parse_args()

    manifest = build_all_fixtures(args.out)
    for name, size in manifest:
        print(f"Generated {name}: {size} bytes")


if __name__ == "__main__":
    main()
