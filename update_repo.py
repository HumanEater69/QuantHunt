import re
with open('backend/reporting.py', 'r', encoding='utf-8') as f:
    text = f.read()

text = text.replace('\"QUANTHUNT\"', '\"QUANTHUNT\"')
text = text.replace('\"QUANTHUNT SECURITY REPORT\"', '\"QUANTHUNT SECURITY REPORT\"')
text = text.replace('\"QuantHunt Security Team\"', '\"QuantHunt Security Team\"')
text = text.replace('\"QuantHunt Cyber Risk Intelligence\"', '\"QuantHunt Cyber Risk Intelligence\"')
text = text.replace('\"QuantHunt Team\"', '\"QuantHunt Team\"')

def_index = text.find('def build_quantum_certificate')
if def_index != -1:
    before = text[:def_index]
    new_code = '''def build_quantum_certificate(scan: dict, avg_risk: float) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=landscape(A4))
    w, h = A4
    w, h = h, w
    label = readiness_label(avg_risk)
    issued_at = datetime.now(timezone.utc)
    valid_until = issued_at + timedelta(days=365)
    margin = 38
    inner_x = margin
    inner_y = margin
    inner_w = w - (margin * 2)
    inner_h = h - (margin * 2)

    c.setFillColor(colors.HexColor("#f7f0df"))
    c.rect(0, 0, w, h, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#efe2c7"))
    c.roundRect(inner_x, inner_y, inner_w, inner_h, 18, fill=1, stroke=0)

    c.setStrokeColor(colors.HexColor("#c8a867"))
    c.setLineWidth(1.8)
    c.roundRect(inner_x + 8, inner_y + 8, inner_w - 16, inner_h - 16, 16, fill=0, stroke=1)

    c.setLineWidth(0.5)
    c.roundRect(inner_x + 12, inner_y + 12, inner_w - 24, inner_h - 24, 12, fill=0, stroke=1)

    _draw_logo_watermark(c, w, h, "QH_CERT_LOGO_PATH", "QUANTHUNT CERTIFIED", opacity=0.09)

    top = h - 100

    c.setFillColor(colors.HexColor("#6d541f"))
    c.setFont("Times-Bold", 36)
    c.drawCentredString(w / 2, top, "CERTIFICATE OF PQC READINESS")

    c.setFillColor(colors.HexColor("#8d6e31"))
    c.setFont("Times-Italic", 15)
    c.drawCentredString(w / 2, top - 32, "This certificate acknowledges that the domain")

    c.setFillColor(colors.HexColor("#654f1f"))
    c.setFont("Times-Bold", 32)
    c.drawCentredString(w / 2, top - 75, str(scan.get("domain", "unknown")))

    c.setFillColor(colors.HexColor("#8d6e31"))
    c.setFont("Times-Italic", 15)
    c.drawCentredString(w / 2, top - 115, "has undergone rigorous Cyber PQC Posture Assessment and achieved a")

    if label == "Fully Quantum Safe":
        badge_color = colors.HexColor("#2d6e4d")
    elif label == "PQC Ready":
        badge_color = colors.HexColor("#8a6a22")
    else:
        badge_color = colors.HexColor("#8b2f2f")

    box_w = 400
    box_h = 44
    box_x = (w - box_w) / 2
    box_y = top - 185

    c.setFillColor(colors.HexColor("#f9f0dc"))
    c.roundRect(box_x - 10, box_y - 10, box_w + 20, box_h + 20, 8, fill=1, stroke=0)

    c.setFillColor(badge_color)
    c.roundRect(box_x, box_y, box_w, box_h, 8, fill=1, stroke=0)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(w / 2, box_y + 16, f"Readiness Label: {label}")

    info_y = box_y - 45
    c.setFillColor(colors.HexColor("#654f1f"))
    c.setFont("Helvetica", 12)
    c.drawCentredString(w / 2, info_y, f"Average HNDL Risk Score: {avg_risk:.2f}")

    bot_y = inner_y + 70

    left_x = inner_x + 140
    c.setFillColor(colors.HexColor("#6e5626"))
    c.setFont("Helvetica", 12)
    c.drawCentredString(left_x, bot_y, issued_at.strftime("%d %b %Y"))
    c.setStrokeColor(colors.HexColor("#b49352"))
    c.line(left_x - 80, bot_y - 12, left_x + 80, bot_y - 12)
    c.setFont("Helvetica", 10)
    c.drawCentredString(left_x, bot_y - 25, "Date of Issue")

    seal_cx = w / 2
    seal_cy = bot_y + 10
    _draw_gold_seal(c, seal_cx, seal_cy, 45, (os.getenv("QH_CERT_SEAL_TEXT") or "Quantum Verified").strip())

    right_x = w - inner_x - 140
    c.setFont("Helvetica-Oblique", 14)
    sig_drawn = _draw_optional_image(c, "QH_CERT_SIGNATURE_PATH", right_x - 60, bot_y - 10, 120, 40)
    if not sig_drawn:
        c.drawCentredString(right_x, bot_y, (os.getenv("QH_TEAM_SIGNATURE") or "QuantHunt Security").strip())
    c.setStrokeColor(colors.HexColor("#b49352"))
    c.line(right_x - 90, bot_y - 12, right_x + 90, bot_y - 12)
    c.setFont("Helvetica", 10)
    c.drawCentredString(right_x, bot_y - 25, "Authorized Signature")

    c.setFont("Helvetica", 8)
    c.drawCentredString(w / 2, inner_y + 20, f"Scan ID: {scan.get('scan_id', 'n/a')}  |  Valid through: {valid_until.strftime('%d %b %Y')}")

    c.save()
    return buf.getvalue()
'''

    with open('backend/reporting.py', 'w', encoding='utf-8') as f:
        f.write(before + new_code)
