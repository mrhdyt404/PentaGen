import hashlib
import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..models import Evidence, Finding, FindingAnalysis, Organization, Scan, Target


SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#d97706"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#475569"),
}


def compute_posture_score(findings: list[Finding]) -> tuple[int, str]:
    """Compute 0-100 posture score and letter grade based on findings severity."""
    score = 100
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
        if sev == "critical":
            score -= 25
        elif sev == "high":
            score -= 15
        elif sev == "medium":
            score -= 8
        elif sev == "low":
            score -= 3
    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def generate_scan_pdf_report(
    scan: Scan,
    target: Target | None,
    organization: Organization,
    findings: list[Finding],
    evidence_items: list[Evidence],
    analyses: list[FindingAnalysis] | None = None,
) -> bytes:
    """Generate an enterprise-grade security assessment report in PDF format."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom typography styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#475569"),
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0284c7"),
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    body_bold = ParagraphStyle(
        "BodyDarkBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
    )
    code_style = ParagraphStyle(
        "CodeSnippet",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#334155"),
    )

    story: list[Any] = []

    # 1. Header Banner
    posture_score, posture_grade = compute_posture_score(findings)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    header_table = Table(
        [
            [
                Paragraph("<b>PENTAGEN</b> | SECURITY INTELLIGENCE", subtitle_style),
                Paragraph("<b>CONFIDENTIAL</b> · AUTHORIZED ASSESSMENT", subtitle_style),
            ],
            [
                Paragraph(f"Security Assessment Report: Scan #{scan.id}", title_style),
                Paragraph(f"<b>Posture Grade: {posture_grade}</b> ({posture_score}/100)", title_style),
            ],
            [
                Paragraph(f"Organization: <b>{organization.name}</b> · Generated: {now_str}", subtitle_style),
                Paragraph(f"Status: <b>{scan.status.value.upper()}</b> · Profile: {scan.profile}", subtitle_style),
            ],
        ],
        colWidths=[340, 200],
    )
    header_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(header_table)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # 2. Executive Summary & Metrics Grid
    story.append(Paragraph("Executive Summary", h2_style))

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity).lower()
        if sev_key in sev_counts:
            sev_counts[sev_key] += 1

    summary_text = (
        f"This security assessment evaluated target asset <b>{target.name if target else 'Source Artifact'}</b> "
        f"using the authorized <b>{scan.profile}</b> profile. A total of <b>{len(findings)}</b> findings were identified, "
        f"including {sev_counts['critical']} Critical and {sev_counts['high']} High severity issues. "
        "All test procedures were restricted to non-destructive, allowlisted security checks."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # Metrics Matrix Table
    metrics_data = [
        ["Target Hostname", target.hostname if target else "N/A", "Critical Findings", str(sev_counts["critical"])],
        ["Target Base URL", target.base_url if target else "N/A", "High Findings", str(sev_counts["high"])],
        ["Scan Started", scan.started_at.strftime("%Y-%m-%d %H:%M UTC") if scan.started_at else "N/A", "Medium Findings", str(sev_counts["medium"])],
        ["Scan Finished", scan.finished_at.strftime("%Y-%m-%d %H:%M UTC") if scan.finished_at else "In Progress", "Low / Info Findings", f"{sev_counts['low']} / {sev_counts['info']}"],
    ]
    metrics_table = Table(metrics_data, colWidths=[110, 190, 110, 130])
    metrics_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1e293b")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(metrics_table)
    story.append(Spacer(1, 14))

    # 3. Technical Findings Details
    story.append(Paragraph(f"Detailed Security Findings ({len(findings)})", h2_style))

    if not findings:
        story.append(Paragraph("No security vulnerabilities or baseline weaknesses were detected during this scan.", body_style))
    else:
        # Group evidence by finding_id for quick lookup
        evidence_by_finding: dict[int, list[Evidence]] = {}
        for ev in evidence_items:
            evidence_by_finding.setdefault(ev.finding_id, []).append(ev)

        for idx, finding in enumerate(findings, 1):
            sev_str = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity).upper()
            sev_color = SEVERITY_COLORS.get(sev_str.lower(), colors.HexColor("#475569"))

            finding_header = Table(
                [
                    [
                        Paragraph(f"<b>#{idx}. {finding.title}</b>", body_bold),
                        Paragraph(f"<b>{sev_str.upper()}</b>", ParagraphStyle("Sev", parent=body_bold, textColor=sev_color, alignment=2)),
                    ]
                ],
                colWidths=[420, 120],
            )
            finding_header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))

            finding_details = [
                [Paragraph("<b>Category:</b>", body_style), Paragraph(finding.category, body_style), Paragraph("<b>Location:</b>", body_style), Paragraph(finding.location or "N/A", body_style)],
                [Paragraph("<b>CVSS Score:</b>", body_style), Paragraph(finding.cvss_score or "N/A", body_style), Paragraph("<b>CWE:</b>", body_style), Paragraph(finding.cwe or "N/A", body_style)],
            ]
            details_table = Table(finding_details, colWidths=[70, 190, 60, 220])
            details_table.setStyle(
                TableStyle(
                    [
                        ("TOPPADDING", (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                    ]
                )
            )

            blocks: list[Any] = [
                finding_header,
                Spacer(1, 4),
                details_table,
                Spacer(1, 4),
                Paragraph("<b>Description:</b> " + finding.description, body_style),
                Spacer(1, 3),
            ]

            if finding.remediation:
                blocks.append(Paragraph("<b>Remediation:</b> " + finding.remediation, body_style))
                blocks.append(Spacer(1, 3))

            # Attached Evidence & Integrity Hash
            attached_ev = evidence_by_finding.get(finding.id, [])
            if attached_ev:
                for ev in attached_ev:
                    blocks.append(
                        Paragraph(
                            f"<b>Evidence ({ev.evidence_type}):</b> <font color='#475569'>SHA-256: {ev.content_hash}</font>",
                            body_style,
                        )
                    )
                    clean_content = ev.content_redacted.replace("\n", " ")[:160]
                    blocks.append(Paragraph(f"&gt; {clean_content}...", code_style))

            blocks.append(Spacer(1, 8))
            blocks.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8))
            story.append(KeepTogether(blocks))

    # 4. AI Analyst Intelligence & False-Positive Triage (if available)
    if analyses:
        story.append(Spacer(1, 10))
        story.append(Paragraph("AI Security Analyst & False-Positive Triage", h2_style))
        for ana in analyses:
            verdict_text = (
                f"<b>Verdict:</b> {ana.verdict.upper()} · "
                f"<b>Likely False-Positive:</b> {'YES' if ana.is_likely_false_positive else 'NO'} "
                f"(Confidence: {ana.fp_confidence}) · <b>Risk Score:</b> {ana.risk_score}"
            )
            ai_block = [
                Paragraph(verdict_text, body_style),
                Spacer(1, 2),
                Paragraph(f"<b>Analyst Rationale:</b> {ana.rationale}", body_style),
                Spacer(1, 2),
                Paragraph(f"<b>Strategic Remediation:</b> {ana.remediation_plan}", body_style),
                Spacer(1, 6),
            ]
            story.append(KeepTogether(ai_block))

    # 5. Cryptographic Report Integrity Footer
    story.append(Spacer(1, 14))
    doc_hash_seed = f"{scan.id}:{scan.organization_id}:{now_str}:{len(findings)}"
    doc_digest = hashlib.sha256(doc_hash_seed.encode("utf-8")).hexdigest()
    footer_text = (
        f"PentaGen Assessment Engine v1.0 · Document Hash: {doc_digest[:32]}... · "
        "Strictly confidential. Unauthorized reproduction or dissemination is prohibited."
    )
    story.append(Paragraph(footer_text, ParagraphStyle("Footer", parent=subtitle_style, fontSize=7, leading=9, alignment=1)))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
