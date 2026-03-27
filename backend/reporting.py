from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
import os
from pathlib import Path
from typing import Iterable

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

def build_scan_pdf(scan: dict) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    findings = scan.get("findings", []) or []
    avg_risk = 0.0
    if findings:
        scores = [float(f.get("hndl_risk_score") or 0) for f in findings]
        avg_risk = sum(scores) / len(scores)

    def draw_report_page_bg() -> None:
        c.setFillColor(colors.HexColor("#f8f3e7"))
        c.rect(0, 0, w, h, fill=1, stroke=0)
        c.setFillColor(colors.HexColor("#efe5d1"))
        c.roundRect(24, 24, w - 48, h - 48, 22, fill=1, stroke=0)
        c.setStrokeColor(colors.HexColor("#d3bc8a"))
        c.setLineWidth(1.4)
        c.roundRect(30, 30, w - 60, h - 60, 20, fill=0, stroke=1)
        _draw_logo_watermark(c, w, h, "QH_CERT_LOGO_PATH", "QUANTHUNT", opacity=0.06)

    draw_report_page_bg()

    c.setFillColor(colors.HexColor("#94712a"))
    c.roundRect(46, h - 126, w - 92, 76, 18, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#fdf5e2"))
    c.setFont("Times-Bold", 25)
    c.drawString(64, h - 84, "QUANTHUNT SECURITY REPORT")
    c.setFont("Helvetica", 10)
    c.drawString(64, h - 101, "Claymorphism Gold Edition")
    c.setFont("Helvetica", 9)
    c.drawString(64, h - 115, "Print-ready intelligence summary")
    _draw_optional_image(c, "QH_CERT_LOGO_PATH", w - 118, h - 108, 56, 56)

    c.setFillColor(colors.HexColor("#f6ecda"))
    c.roundRect(46, h - 232, w - 92, 88, 14, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#d2ba88"))
    c.setLineWidth(1)
    c.roundRect(46, h - 232, w - 92, 88, 14, fill=0, stroke=1)

    c.setFillColor(colors.HexColor("#5b471f"))
    c.setFont("Helvetica-Bold", 11)
    c.drawString(62, h - 166, f"Domain: {scan.get('domain', 'n/a')}")
    c.drawString(62, h - 184, f"Scan ID: {scan.get('scan_id', 'n/a')}")
    c.drawString(62, h - 202, f"Status: {scan.get('status', 'n/a')}  Progress: {scan.get('progress', 0)}%")

    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(w - 62, h - 166, f"Findings: {len(findings)}")
    c.drawRightString(w - 62, h - 184, f"Avg Risk: {avg_risk:.2f}")
    c.drawRightString(w - 62, h - 202, f"Readiness: {readiness_label(avg_risk)}")

    page_no = 1
    y = h - 266
    c.setFillColor(colors.HexColor("#7c6228"))
    c.setFont("Helvetica-Bold", 13)
    c.drawString(52, y, "Top Findings and Recommendations")
    c.setStrokeColor(colors.HexColor("#c9b27d"))
    c.setLineWidth(0.8)
    c.line(52, y - 5, w - 52, y - 5)
    y -= 20

    for finding in findings:
        recs = list(finding.get("recommendations", []) or [])[:3]
        if not recs:
            recs = ["No recommendation generated for this finding."]
        wrapped_recs: list[str] = []
        for rec in recs:
            lines = _wrap_text_by_width(c, rec, w - 138, "Helvetica", 9)
            if not lines:
                continue
            wrapped_recs.extend(lines[:2])
        if not wrapped_recs:
            wrapped_recs = ["No recommendation generated for this finding."]

        card_height = min(176, max(122, 88 + (len(wrapped_recs) * 11)))
        if y - card_height < 48:
            _draw_report_signature(c, w, page_no)
            c.showPage()
            page_no += 1
            draw_report_page_bg()
            y = h - 72
            c.setFillColor(colors.HexColor("#7c6228"))
            c.setFont("Helvetica-Bold", 13)
            c.drawString(52, y, "Findings (continued)")
            c.setStrokeColor(colors.HexColor("#c9b27d"))
            c.setLineWidth(0.8)
            c.line(52, y - 5, w - 52, y - 5)
            y -= 20

        c.setFillColor(colors.HexColor("#f9f1df"))
        c.roundRect(46, y - card_height, w - 92, card_height, 12, fill=1, stroke=0)
        c.setStrokeColor(colors.HexColor("#d7c090"))
        c.roundRect(46, y - card_height, w - 92, card_height, 12, fill=0, stroke=1)

        c.setFillColor(colors.HexColor("#5c4720"))
        c.setFont("Helvetica-Bold", 11)
        c.drawString(60, y - 18, f"Asset: {finding.get('asset', 'n/a')}")
        c.setFont("Helvetica", 10)
        c.drawString(
            60,
            y - 34,
            f"Score: {finding.get('hndl_risk_score', 'n/a')}   Label: {finding.get('label', 'n/a')}",
        )
        c.drawString(
            60,
            y - 49,
            f"TLS: {finding.get('tls', {}).get('tls_version', 'n/a')}   Cipher: {finding.get('tls', {}).get('cipher_suite', 'n/a')}",
        )

        rec_y = y - 66
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor("#3d4f66"))
        for idx, line in enumerate(wrapped_recs):
            prefix = "- " if idx == 0 or (idx % 2 == 0) else "  "
            c.drawString(66, rec_y, f"{prefix}{line}")
            rec_y -= 12

        y -= card_height + 10

    _draw_report_signature(c, w, page_no)

    c.showPage()
    c.save()
    buf.seek(0)
    return buf.read()

def readiness_label(avg_risk: float) -> str:
    if avg_risk <= 60:
        return "Quantum-Safe"
    if avg_risk <= 80:
        return "PQC Ready"
    return "CRITICAL EXPOSURE"

def _draw_optional_image(c: canvas.Canvas, env_var: str, x: float, y: float, width: float, height: float) -> bool:
    raw_path = (os.getenv(env_var) or "").strip()
    if not raw_path:
        return False
    path = Path(raw_path)
    if not path.exists() or not path.is_file():
        return False
    try:
        img = ImageReader(str(path))
        c.drawImage(img, x, y, width=width, height=height, preserveAspectRatio=True, mask="auto")
        return True
    except Exception:
        return False

def _draw_gold_seal(c: canvas.Canvas, cx: float, cy: float, radius: float, text: str) -> None:
    c.setFillColor(colors.HexColor("#d1aa46"))
    c.circle(cx, cy, radius, fill=1, stroke=0)
    c.setStrokeColor(colors.HexColor("#8f6a1a"))
    c.setLineWidth(1.6)
    c.circle(cx, cy, radius - 2, fill=0, stroke=1)
    c.setStrokeColor(colors.HexColor("#f2d37b"))
    c.setLineWidth(1.0)
    c.circle(cx, cy, radius - 6, fill=0, stroke=1)
    c.setFillColor(colors.HexColor("#7d5b15"))
    c.setFont("Helvetica-Bold", 8)
    c.drawCentredString(cx, cy + 2, "CERTIFIED")
    c.setFont("Helvetica", 6)
    c.drawCentredString(cx, cy - 8, text[:26])

def _draw_watermark(c: canvas.Canvas, w: float, h: float, text: str) -> None:
    c.saveState()
    c.translate(w * 0.56, h * 0.46)
    c.rotate(32)
    c.setFillColor(colors.Color(0.15, 0.32, 0.52, alpha=0.08))
    c.setFont("Helvetica-Bold", 54)
    c.drawCentredString(0, 0, text)
    c.restoreState()

def _draw_logo_watermark(c: canvas.Canvas, w: float, h: float, env_var: str, fallback_text: str, opacity: float = 0.08) -> None:
    path = (os.getenv(env_var) or "").strip()
    if path and Path(path).exists():
        try:
            c.saveState()
            c.translate(w / 2, h / 2)
            c.rotate(28)
            c.setFillAlpha(opacity)
            img = ImageReader(path)
            size = min(w, h) * 0.54
            c.drawImage(img, -size / 2, -size / 2, width=size, height=size, preserveAspectRatio=True, mask="auto")
            c.restoreState()
            return
        except Exception:
            pass
    _draw_watermark(c, w, h, fallback_text)

def _wrap_text_by_width(c: canvas.Canvas, text: str, max_width: float, font_name: str, font_size: float) -> list[str]:
    words = str(text or "").split()
    if not words:
        return []
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if c.stringWidth(candidate, font_name, font_size) <= max_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines

def _draw_report_signature(c: canvas.Canvas, page_width: float, page_number: int | None = None) -> None:
    team_name = (os.getenv("QH_TEAM_NAME") or "QuantHunt Security Team").strip()
    sig_text = (os.getenv("QH_TEAM_SIGNATURE") or team_name).strip()
    sig_path = (os.getenv("QH_CERT_SIGNATURE_PATH") or "").strip()
    c.setStrokeColor(colors.HexColor("#bda66f"))
    c.line(52, 52, page_width - 52, 52)
    c.setFillColor(colors.HexColor("#6b5630"))
    c.setFont("Helvetica-Bold", 9)
    c.drawString(56, 38, f"Issued by: {team_name}")
    c.setFont("Helvetica", 9)
    c.drawRightString(page_width - 56, 38, "Signature")
    if page_number is not None:
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#876f3c"))
        c.drawCentredString(page_width / 2, 38, f"Page {page_number}")
    if sig_path and Path(sig_path).exists():
        _draw_optional_image(c, "QH_CERT_SIGNATURE_PATH", page_width - 172, 58, 110, 28)
    else:
        c.setFont("Times-Italic", 15)
        c.setFillColor(colors.HexColor("#7a6541"))
        c.drawRightString(page_width - 56, 66, sig_text)

def _fit_text(c: canvas.Canvas, text: str, font_name: str, font_size: float, max_width: float) -> str:
    value = str(text or "")
    if max_width <= 0:
        return ""
    if c.stringWidth(value, font_name, font_size) <= max_width:
        return value
    ellipsis = "..."
    if c.stringWidth(ellipsis, font_name, font_size) > max_width:
        return ""
    low = 0
    high = len(value)
    while low < high:
        mid = (low + high + 1) // 2
        candidate = value[:mid] + ellipsis
        if c.stringWidth(candidate, font_name, font_size) <= max_width:
            low = mid
        else:
            high = mid - 1
    return value[:low] + ellipsis

def build_quantum_certificate(
    scan: dict,
    avg_risk: float,
    eligible: bool = True,
    reasons: list[str] | None = None,
) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=landscape(A4))
    w, h = A4
    w, h = h, w
    label = readiness_label(avg_risk)
    fail_reasons = list(reasons or [])
    issued_at = datetime.now(timezone.utc)
    valid_until = issued_at + timedelta(days=365)
    margin = 38
    inner_x = margin
    inner_y = margin
    inner_w = w - (margin * 2)
    inner_h = h - (margin * 2)

    page_bg = "#f7f0df" if eligible else "#f6e7e9"
    inner_bg = "#efe2c7" if eligible else "#edd3d7"
    border_col = "#c8a867" if eligible else "#b06673"
    text_primary = "#6d541f" if eligible else "#7a2635"
    text_secondary = "#8d6e31" if eligible else "#9b3c4d"
    text_domain = "#654f1f" if eligible else "#6a1f2c"

    c.setFillColor(colors.HexColor(page_bg))
    c.rect(0, 0, w, h, fill=1, stroke=0)
    c.setFillColor(colors.HexColor(inner_bg))
    c.roundRect(inner_x, inner_y, inner_w, inner_h, 18, fill=1, stroke=0)

    c.setStrokeColor(colors.HexColor(border_col))
    c.setLineWidth(1.8)
    c.roundRect(inner_x + 8, inner_y + 8, inner_w - 16, inner_h - 16, 16, fill=0, stroke=1)

    c.setLineWidth(0.5)
    c.roundRect(inner_x + 12, inner_y + 12, inner_w - 24, inner_h - 24, 12, fill=0, stroke=1)

    _draw_logo_watermark(
        c,
        w,
        h,
        "QH_CERT_LOGO_PATH",
        "QUANTHUNT CERTIFIED" if eligible else "QUANTHUNT FAILED",
        opacity=0.09,
    )

    top = h - 100

    c.setFillColor(colors.HexColor(text_primary))
    c.setFont("Times-Bold", 36)
    c.drawCentredString(
        w / 2,
        top,
        "CERTIFICATE OF PQC READINESS" if eligible else "PQC READINESS FAILURE CERTIFICATE",
    )

    c.setFillColor(colors.HexColor(text_secondary))
    c.setFont("Times-Italic", 15)
    c.drawCentredString(
        w / 2,
        top - 32,
        "This certificate acknowledges that the domain"
        if eligible
        else "This document certifies the domain failed strict PQC readiness checks",
    )

    c.setFillColor(colors.HexColor(text_domain))
    c.setFont("Times-Bold", 32)
    c.drawCentredString(w / 2, top - 75, str(scan.get("domain", "unknown")))

    c.setFillColor(colors.HexColor(text_secondary))
    c.setFont("Times-Italic", 15)
    c.drawCentredString(
        w / 2,
        top - 115,
        "has undergone rigorous Cyber PQC Posture Assessment and achieved a"
        if eligible
        else "after rigorous Cyber PQC Posture Assessment, readiness criteria were not met",
    )

    if not eligible:
        badge_color = colors.HexColor("#8b2f2f")
    elif label == "Quantum-Safe":
        badge_color = colors.HexColor("#2d6e4d")
    elif label == "PQC Ready":
        badge_color = colors.HexColor("#8a6a22")
    else:
        badge_color = colors.HexColor("#8b2f2f")

    box_w = 400
    box_h = 44
    box_x = (w - box_w) / 2
    box_y = top - 185

    c.setFillColor(colors.HexColor("#f9f0dc" if eligible else "#f6dde1"))
    c.roundRect(box_x - 10, box_y - 10, box_w + 20, box_h + 20, 8, fill=1, stroke=0)

    c.setFillColor(badge_color)
    c.roundRect(box_x, box_y, box_w, box_h, 8, fill=1, stroke=0)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(
        w / 2,
        box_y + 16,
        f"Readiness Label: {label}" if eligible else "Readiness Label: FAILED",
    )

    info_y = box_y - 45
    c.setFillColor(colors.HexColor(text_domain))
    c.setFont("Helvetica", 12)
    c.drawCentredString(w / 2, info_y, f"Average HNDL Risk Score: {avg_risk:.2f}")

    if not eligible:
        reason_top = info_y - 26
        c.setFillColor(colors.HexColor("#742b39"))
        c.setFont("Helvetica-Bold", 11)
        c.drawCentredString(w / 2, reason_top, "FAILURE REASONS")
        c.setFont("Helvetica", 10)
        y = reason_top - 16
        for reason in fail_reasons[:5]:
            line = _fit_text(c, f"- {reason}", "Helvetica", 10, inner_w - 140)
            c.drawString(inner_x + 70, y, line)
            y -= 14

    bot_y = inner_y + 70

    left_x = inner_x + 140
    c.setFillColor(colors.HexColor("#6e5626" if eligible else "#6b2b39"))
    c.setFont("Helvetica", 12)
    c.drawCentredString(left_x, bot_y, issued_at.strftime("%d %b %Y"))
    c.setStrokeColor(colors.HexColor("#b49352" if eligible else "#b56f7d"))
    c.line(left_x - 80, bot_y - 12, left_x + 80, bot_y - 12)
    c.setFont("Helvetica", 10)
    c.drawCentredString(left_x, bot_y - 25, "Date of Issue")

    seal_cx = w / 2
    seal_cy = bot_y + 10
    _draw_gold_seal(
        c,
        seal_cx,
        seal_cy,
        45,
        (os.getenv("QH_CERT_SEAL_TEXT") or ("Quantum Verified" if eligible else "Readiness Failed")).strip(),
    )

    right_x = w - inner_x - 140
    c.setFont("Helvetica-Oblique", 14)
    sig_drawn = _draw_optional_image(c, "QH_CERT_SIGNATURE_PATH", right_x - 60, bot_y - 10, 120, 40)
    if not sig_drawn:
        c.drawCentredString(right_x, bot_y, (os.getenv("QH_TEAM_SIGNATURE") or "QuantHunt Security").strip())
    c.setStrokeColor(colors.HexColor("#b49352" if eligible else "#b56f7d"))
    c.line(right_x - 90, bot_y - 12, right_x + 90, bot_y - 12)
    c.setFont("Helvetica", 10)
    c.drawCentredString(right_x, bot_y - 25, "Authorized Signature")

    c.setFont("Helvetica", 8)
    foot = (
        f"Scan ID: {scan.get('scan_id', 'n/a')}  |  Valid through: {valid_until.strftime('%d %b %Y')}"
        if eligible
        else f"Scan ID: {scan.get('scan_id', 'n/a')}  |  Status: Failed strict PQC readiness"
    )
    c.drawCentredString(w / 2, inner_y + 20, foot)

    c.save()
    return buf.getvalue()
