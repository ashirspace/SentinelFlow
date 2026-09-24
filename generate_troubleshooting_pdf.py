import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)

def create_guide_pdf(output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#475569'),
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Header1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#0284c7'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Header2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor('#334155'),
        spaceAfter=5
    )

    bullet_style = ParagraphStyle(
        'BulletDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155'),
        leftIndent=15,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor('#0f172a'),
        backColor=colors.HexColor('#f1f5f9'),
        borderPadding=5,
        spaceBefore=3,
        spaceAfter=5
    )

    callout_style = ParagraphStyle(
        'Callout',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#b45309'),
        spaceAfter=4
    )

    story = []

    # Title Banner
    story.append(Paragraph("SentinelFlow &amp; Akamai Integration Guide", title_style))
    story.append(Paragraph("Complete Point-Wise Problem Solving &amp; Troubleshooting Manual<br/><b>Target System:</b> siem.abpplus.com | <b>Source:</b> akamai-abpplus", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

    # SECTION 1: ROOT CAUSE SUMMARY
    story.append(Paragraph("1. Root Cause Summary (Asli Problem Kya Thi?)", h1_style))
    story.append(Paragraph("Live server audit aur test logs run karne ke baad 2 mukhya kaaran mile:", body_style))
    
    summary_data = [
        [Paragraph("<b>Component</b>", body_style), Paragraph("<b>Root Cause (Samasya)</b>", body_style), Paragraph("<b>Impact &amp; Status</b>", body_style)],
        [
            Paragraph("<b>Akamai Gzip Compression</b>", body_style),
            Paragraph("Akamai DataStream 2 by-default logs ko <b>Gzip Compress</b> karke bhejta hai. Live server par gzip decompression code deploy nahi tha.", body_style),
            Paragraph("<font color='#dc2626'><b>400 Bad Request:</b></font> Server compressed bytes ko invalid JSON samajhkar reject kar raha tha.", body_style)
        ],
        [
            Paragraph("<b>API Key Outdated / Mismatched</b>", body_style),
            Paragraph("Source 26-August ko bana tha. Plaintext key expire/lost ho gayi thi.", body_style),
            Paragraph("<font color='#059669'><b>Resolved:</b></font> Nayi verified key generate kar di gayi hai jo direct test me <b>200 OK</b> pass hui.", body_style)
        ],
        [
            Paragraph("<b>Fortinet Firewall Interception</b>", body_style),
            Paragraph("Office/College network par FortiGate firewall <i>siem.abpplus.com</i> ko 'Newly Observed Domain' bolkar block karta hai.", body_style),
            Paragraph("<font color='#dc2626'><b>Network Block:</b></font> Browser me red SSL warning aur connection closed error aata hai.", body_style)
        ]
    ]
    t_summary = Table(summary_data, colWidths=[120, 260, 160])
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 10))

    # SECTION 2: AKAMAI CONTROL CENTER STEP-BY-STEP FIXES
    story.append(Paragraph("2. Akamai Control Center Settings (Point-Wise Solution)", h1_style))
    story.append(Paragraph("Akamai Control Center me jakar DataStream 2 me ye 6 settings verify aur update karein:", body_style))

    story.append(Paragraph("<b>Point 2.1 — Compression: Turn OFF (Sabse Zaroori)</b>", h2_style))
    story.append(Paragraph("• <b>Action:</b> Destination settings me <b>Compression</b> ko <b>None / Off (Do not gzip)</b> select karein.<br/>• <b>Kyun:</b> Server uncompressed JSON ko 100% successfully accept karta hai. Gzip on hone se server 400 error de deta hai.", bullet_style))

    story.append(Paragraph("<b>Point 2.2 — Destination URL Format</b>", h2_style))
    story.append(Paragraph("• <b>Action:</b> Endpoint URL me exact per-source path dalein:<br/>&nbsp;&nbsp;&nbsp;&nbsp;<code>https://siem.abpplus.com/api/integrations/akamai/akamai-abpplus/logs</code><br/>• <b>Dhyan dein:</b> Generic URL (jaise sirf <i>siem.abpplus.com</i> ya <i>/api/v1/ingest</i>) na dalein.", bullet_style))

    story.append(Paragraph("<b>Point 2.3 — Custom Authentication Header</b>", h2_style))
    story.append(Paragraph("• <b>Authentication Type:</b> <code>None</code> chunein.<br/>• <b>Custom Request Header Name:</b> <code>X-Ingest-Key</code><br/>• <b>Header Value (Live Verified Key):</b><br/>&nbsp;&nbsp;&nbsp;&nbsp;<code>sfk_p0mzD6IeYSOdnL9TatMWkwWEEMBRokkoYpZZOnjQUl8</code>", bullet_style))

    story.append(Paragraph("<b>Point 2.4 — Data Format &amp; Method</b>", h2_style))
    story.append(Paragraph("• <b>Method:</b> <code>POST</code><br/>• <b>Format:</b> <code>JSON</code> ya <code>Structured JSON</code> (W3C ya Apache combined na chunein).<br/>• <b>Content-Type:</b> <code>application/json</code>", bullet_style))

    story.append(Paragraph("<b>Point 2.5 — Stream Activation (Production vs Staging)</b>", h2_style))
    story.append(Paragraph("• <b>Action:</b> Stream ko <b>Activate on Production</b> karein.<br/>• <b>Propagation Time:</b> Akamai global edge servers par config failane me <b>15 se 45 minute</b> lagata hai.", bullet_style))

    story.append(Paragraph("<b>Point 2.6 — Property Association</b>", h2_style))
    story.append(Paragraph("• DataStream configuration ke andar apni live website ki <b>Property (CDN hostname)</b> select honi chahiye. Agar property link nahi hogi to Akamai 0 logs capture karega.", bullet_style))

    story.append(Spacer(1, 10))

    # SECTION 3: TESTING & VERIFYING
    story.append(Paragraph("3. Verification Test (cURL Se Test Karein)", h1_style))
    story.append(Paragraph("Akamai ke bina bhi aap apne terminal se turant check kar sakte hain ki SentinelFlow logs accept kar raha hai:", body_style))

    curl_cmd = (
        'curl -i -X POST "https://siem.abpplus.com/api/integrations/akamai/akamai-abpplus/logs" \\\n'
        '  -H "X-Ingest-Key: sfk_p0mzD6IeYSOdnL9TatMWkwWEEMBRokkoYpZZOnjQUl8" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'[{\n'
        '    "type": "akamai_siem",\n'
        '    "reqTimeSec": "1788854400",\n'
        '    "cliIP": "203.0.113.195",\n'
        '    "httpMessage": {\n'
        '      "reqMethod": "GET",\n'
        '      "reqPath": "/articles/news-today",\n'
        '      "statusCode": "200",\n'
        '      "reqHost": "abpplus.com"\n'
        '    },\n'
        '    "geo": {"country": "IN"}\n'
        '  }]\''
    )
    story.append(Paragraph(f"<font face='Courier' size='7.5'>{curl_cmd.replace(chr(10), '<br/>').replace(' ', '&nbsp;')}</font>", code_style))
    story.append(Paragraph("<b>Expected Output:</b> <code>HTTP/1.1 200 OK</code> | <code>{\"ingested\":1,\"alerts\":0,\"source\":\"akamai-abpplus\"}</code>", callout_style))

    story.append(PageBreak())

    # SECTION 4: PERMANENT CODE DEPLOYMENT (SENTINELFLOW GZIP FIX)
    story.append(Paragraph("4. SentinelFlow Server Fix (Gzip Support Enable Karna)", h1_style))
    story.append(Paragraph("Agar aap chahte hain ki Akamai se <b>Gzip Compression ON</b> hone par bhi SentinelFlow logs reject na kare, to local branch <i>rohit</i> me jo gzip decompression code likha hai use server par deploy karein:", body_style))

    story.append(Paragraph("<b>File: backend/akamai_ingest.py me ye change hai:</b>", h2_style))
    code_diff = (
        'import gzip\n'
        'import json\n\n'
        'def parse_akamai_payload(raw: bytes) -> List[Dict[str, Any]]:\n'
        '    if not raw:\n'
        '        raise ValueError("empty Akamai payload")\n\n'
        '    # Auto-detect and decompress gzip payloads from Akamai\n'
        '    if raw.startswith(b"\\x1f\\x8b"):\n'
        '        try:\n'
        '            raw = gzip.decompress(raw)\n'
        '        except Exception as exc:\n'
        '            raise ValueError(f"failed to decompress gzip: {exc}")\n\n'
        '    text = raw.decode("utf-8", errors="replace").strip()\n'
        '    ...'
    )
    story.append(Paragraph(f"<font face='Courier' size='7.5'>{code_diff.replace(chr(10), '<br/>').replace(' ', '&nbsp;')}</font>", code_style))

    story.append(Paragraph("<b>Server par deploy karne ke steps:</b>", h2_style))
    story.append(Paragraph("1. Local code commit karein: <code>git add backend/akamai_ingest.py &amp;&amp; git commit -m 'Support gzip Akamai logs'</code><br/>"
                           "2. GitHub par push karein: <code>git push origin rohit</code><br/>"
                           "3. Production server (34.131.111.51) par <code>git pull</code> karke FastAPI restart karein.", bullet_style))

    story.append(Spacer(1, 10))

    # SECTION 5: FORTINET FIREWALL UNBLOCK GUIDE
    story.append(Paragraph("5. Fortinet Firewall Block Ko Solve Karna", h1_style))
    story.append(Paragraph("Aapke computer par <i>siem.abpplus.com</i> kholne par jo error aata hai, wo office/institute ke <b>FortiGate Firewall</b> ki wajah se hai.", body_style))

    story.append(Paragraph("<b>Option A: Mobile Hotspot (Turant Kaam Karega)</b>", h2_style))
    story.append(Paragraph("• Apne computer ko Mobile Hotspot (4G/5G) se connect karein. Mobile par koi Fortinet firewall nahi hota, isliye website seedha bina warning ke khulegi.", bullet_style))

    story.append(Paragraph("<b>Option B: FortiGuard Re-evaluation Request</b>", h2_style))
    story.append(Paragraph("• FortiGuard Web Filter portal par request daalein:<br/>&nbsp;&nbsp;&nbsp;&nbsp;<code>https://globalurl.fortinet.net/rate/submit.php</code><br/>• Domain <b>siem.abpplus.com</b> daalkar category <b>Information Technology</b> select karein. 24h me globally unblock ho jayega.", bullet_style))

    story.append(Paragraph("<b>Option C: Cloudflare Proxy (Best Permanent Solution)</b>", h2_style))
    story.append(Paragraph("• Apne DNS manager me <i>siem.abpplus.com</i> ka <b>Cloudflare Proxy (Orange Cloud)</b> enable karein. Isse enterprise firewalls ise newly observed domain samajh kar block nahi karenge.", bullet_style))

    story.append(Spacer(1, 10))

    # SECTION 6: QUICK REFERENCE CHEAT SHEET
    story.append(Paragraph("6. Quick Configuration Cheat Sheet", h1_style))
    
    table_data = [
        [Paragraph("<b>Parameter</b>", body_style), Paragraph("<b>Correct Value to Set</b>", body_style)],
        [Paragraph("Destination Type", body_style), Paragraph("Custom HTTPS", body_style)],
        [Paragraph("Endpoint URL", body_style), Paragraph("<code>https://siem.abpplus.com/api/integrations/akamai/akamai-abpplus/logs</code>", body_style)],
        [Paragraph("HTTP Method", body_style), Paragraph("POST", body_style)],
        [Paragraph("Authentication", body_style), Paragraph("None", body_style)],
        [Paragraph("Custom Header Name", body_style), Paragraph("<code>X-Ingest-Key</code>", body_style)],
        [Paragraph("Custom Header Value", body_style), Paragraph("<code>sfk_p0mzD6IeYSOdnL9TatMWkwWEEMBRokkoYpZZOnjQUl8</code>", body_style)],
        [Paragraph("Compression", body_style), Paragraph("<b>None / Off (Do not gzip)</b>", body_style)],
        [Paragraph("Format / Content-Type", body_style), Paragraph("JSON / application/json", body_style)],
        [Paragraph("Admin Login (UI)", body_style), Paragraph("admin@sentinelflow.io / Admin@12345", body_style)],
        [Paragraph("Local Ingest URL", body_style), Paragraph("http://localhost:8000/api/v1/ingest", body_style)],
    ]
    t_ref = Table(table_data, colWidths=[160, 380])
    t_ref.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_ref)

    # Build PDF
    doc.build(story)
    print("PDF generated successfully at:", output_path)

if __name__ == "__main__":
    out1 = r"C:\Users\Bharat Computers\SentinelFlow\SentinelFlow_Akamai_Troubleshooting_Guide.pdf"
    out2 = r"C:\Users\Bharat Computers\.gemini\antigravity\brain\fdfe2cb8-ff99-4611-a675-122f08142095\SentinelFlow_Akamai_Troubleshooting_Guide.pdf"
    create_guide_pdf(out1)
    create_guide_pdf(out2)
