from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)

from reportlab.lib.enums import TA_CENTER

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

from reportlab.lib.units import mm

from datetime import datetime

import os


# =========================================================
# REPORT DIRECTORY
# =========================================================

REPORT_FOLDER = "reports"

os.makedirs(
    REPORT_FOLDER,
    exist_ok=True
)


# =========================================================
# PAGE HEADER / FOOTER
# =========================================================

def add_page_number(canvas, document):

    canvas.saveState()

    canvas.setFont(
        "Helvetica",
        8
    )

    canvas.drawString(
        20 * mm,
        10 * mm,
        "Cyber Triage Tool | Digital Forensic Investigation"
    )

    canvas.drawRightString(
        190 * mm,
        10 * mm,
        f"Page {document.page}"
    )

    canvas.restoreState()


# =========================================================
# GENERATE PDF REPORT
# =========================================================

def generate_pdf_report(
    filename,
    results
):

    # -----------------------------------------------------
    # CREATE UNIQUE REPORT NAME
    # -----------------------------------------------------

    base_name = os.path.splitext(
        filename
    )[0]

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    report_filename = (
        f"{base_name}_forensic_report_"
        f"{timestamp}.pdf"
    )

    report_path = os.path.join(
        REPORT_FOLDER,
        report_filename
    )


    # -----------------------------------------------------
    # PDF DOCUMENT
    # -----------------------------------------------------

    document = SimpleDocTemplate(

        report_path,

        pagesize=A4,

        rightMargin=20 * mm,

        leftMargin=20 * mm,

        topMargin=20 * mm,

        bottomMargin=20 * mm

    )


    # -----------------------------------------------------
    # STYLES
    # -----------------------------------------------------

    styles = getSampleStyleSheet()


    title_style = ParagraphStyle(

        "ReportTitle",

        parent=styles["Title"],

        alignment=TA_CENTER,

        fontSize=20,

        leading=24,

        spaceAfter=8

    )


    subtitle_style = ParagraphStyle(

        "Subtitle",

        parent=styles["Normal"],

        alignment=TA_CENTER,

        fontSize=11,

        textColor=colors.grey,

        spaceAfter=20

    )


    heading_style = ParagraphStyle(

        "SectionHeading",

        parent=styles["Heading2"],

        fontSize=14,

        leading=18,

        spaceBefore=12,

        spaceAfter=8

    )


    normal_style = ParagraphStyle(

        "NormalText",

        parent=styles["BodyText"],

        fontSize=10,

        leading=14

    )


    small_style = ParagraphStyle(

        "SmallText",

        parent=styles["BodyText"],

        fontSize=8,

        leading=11

    )


    # -----------------------------------------------------
    # GET RESULTS SAFELY
    # -----------------------------------------------------

    risk_score = results.get(
        "risk_score",
        0
    )

    risk_level = results.get(
        "risk_level",
        "Unknown"
    )

    total_iocs = results.get(
        "total_iocs",
        0
    )

    total_findings = results.get(
        "total_findings",
        0
    )

    anomaly = results.get(
        "anomaly",
        False
    )

    ai_status = results.get(
        "status",
        "Unknown"
    )

    ai_score = results.get(
        "score",
        0
    )

    iocs = results.get(
        "iocs",
        []
    )

    findings = results.get(
        "findings",
        []
    )


    # -----------------------------------------------------
    # STORY
    # -----------------------------------------------------

    content = []


    # =====================================================
    # TITLE
    # =====================================================

    content.append(

        Paragraph(
            "CYBER TRIAGE TOOL",
            title_style
        )

    )


    content.append(

        Paragraph(
            "Automated Digital Forensic Investigation Report",
            subtitle_style
        )

    )


    # Report generation information

    content.append(

        Paragraph(

            "<b>Report Generated:</b> "
            + datetime.now().strftime(
                "%d %B %Y, %H:%M:%S"
            ),

            normal_style

        )

    )


    content.append(
        Spacer(1, 12)
    )


    # =====================================================
    # 1. INVESTIGATION INFORMATION
    # =====================================================

    content.append(

        Paragraph(
            "1. Investigation Information",
            heading_style
        )

    )


    investigation_data = [

        [
            Paragraph(
                "<b>Evidence File</b>",
                small_style
            ),

            Paragraph(
                str(filename),
                small_style
            )
        ],

        [
            Paragraph(
                "<b>Investigation Date</b>",
                small_style
            ),

            Paragraph(
                datetime.now().strftime(
                    "%d-%m-%Y %H:%M:%S"
                ),
                small_style
            )
        ],

        [
            Paragraph(
                "<b>Risk Score</b>",
                small_style
            ),

            Paragraph(
                f"{risk_score} / 100",
                small_style
            )
        ],

        [
            Paragraph(
                "<b>Risk Level</b>",
                small_style
            ),

            Paragraph(
                str(risk_level),
                small_style
            )
        ]

    ]


    investigation_table = Table(

        investigation_data,

        colWidths=[
            55 * mm,
            105 * mm
        ]

    )


    investigation_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.lightgrey
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )

        ])

    )


    content.append(
        investigation_table
    )


    # =====================================================
    # 2. EXECUTIVE SUMMARY
    # =====================================================

    content.append(

        Paragraph(
            "2. Executive Summary",
            heading_style
        )

    )


    if risk_level == "Critical":

        summary = (

            "The forensic analysis identified "
            "<b>critical-risk activity</b> within "
            "the submitted evidence. Multiple "
            "suspicious indicators require immediate "
            "review and appropriate incident-response "
            "actions."

        )

    elif risk_level == "High":

        summary = (

            "The forensic analysis identified "
            "<b>high-risk activity</b> within the "
            "submitted evidence. The findings should "
            "be reviewed by a qualified investigator."

        )

    elif risk_level == "Medium":

        summary = (

            "The forensic analysis identified "
            "<b>moderate-risk indicators</b>. "
            "Additional investigation is recommended "
            "to determine whether the observed activity "
            "represents a security incident."

        )

    else:

        summary = (

            "The forensic analysis did not identify "
            "significant suspicious activity based "
            "on the implemented detection and "
            "risk-assessment techniques."

        )


    content.append(

        Paragraph(
            summary,
            normal_style
        )

    )


    content.append(
        Spacer(1, 8)
    )


    content.append(

        Paragraph(

            f"The analysis identified "
            f"<b>{total_iocs}</b> Indicators of "
            f"Compromise and "
            f"<b>{total_findings}</b> suspicious "
            f"findings.",

            normal_style

        )

    )


    # =====================================================
    # 3. RISK ASSESSMENT
    # =====================================================

    content.append(

        Paragraph(
            "3. Risk Assessment",
            heading_style
        )

    )


    risk_data = [

        [
            Paragraph(
                "<b>Risk Metric</b>",
                small_style
            ),

            Paragraph(
                "<b>Result</b>",
                small_style
            )
        ],

        [
            Paragraph(
                "Risk Score",
                small_style
            ),

            Paragraph(
                f"{risk_score} / 100",
                small_style
            )
        ],

        [
            Paragraph(
                "Risk Classification",
                small_style
            ),

            Paragraph(
                str(risk_level),
                small_style
            )
        ],

        [
            Paragraph(
                "IOC Count",
                small_style
            ),

            Paragraph(
                str(total_iocs),
                small_style
            )
        ],

        [
            Paragraph(
                "Suspicious Findings",
                small_style
            ),

            Paragraph(
                str(total_findings),
                small_style
            )
        ]

    ]


    risk_table = Table(

        risk_data,

        colWidths=[
            80 * mm,
            80 * mm
        ]

    )


    risk_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )

        ])

    )


    content.append(
        risk_table
    )


    # =====================================================
    # 4. IOC ANALYSIS
    # =====================================================

    content.append(

        Paragraph(
            "4. Indicators of Compromise Analysis",
            heading_style
        )

    )


    content.append(

        Paragraph(

            f"Total Indicators of Compromise detected: "
            f"<b>{total_iocs}</b>",

            normal_style

        )

    )


    content.append(
        Spacer(1, 8)
    )


    if iocs:

        ioc_data = [

            [
                Paragraph(
                    "<b>No.</b>",
                    small_style
                ),

                Paragraph(
                    "<b>Indicator of Compromise</b>",
                    small_style
                )
            ]

        ]


        for index, ioc in enumerate(
            iocs,
            start=1
        ):

            ioc_data.append(

                [

                    Paragraph(
                        str(index),
                        small_style
                    ),

                    Paragraph(
                        str(ioc),
                        small_style
                    )

                ]

            )


        ioc_table = Table(

            ioc_data,

            colWidths=[
                20 * mm,
                140 * mm
            ]

        )


        ioc_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )

            ])

        )


        content.append(
            ioc_table
        )

    else:

        content.append(

            Paragraph(
                "No Indicators of Compromise were detected.",
                normal_style
            )

        )


    # =====================================================
    # 5. SUSPICIOUS FINDINGS
    # =====================================================

    content.append(

        Paragraph(
            "5. Suspicious Findings",
            heading_style
        )

    )


    content.append(

        Paragraph(

            f"Total suspicious findings: "
            f"<b>{total_findings}</b>",

            normal_style

        )

    )


    content.append(
        Spacer(1, 8)
    )


    if findings:

        finding_data = [

            [
                Paragraph(
                    "<b>No.</b>",
                    small_style
                ),

                Paragraph(
                    "<b>Finding</b>",
                    small_style
                )
            ]

        ]


        for index, finding in enumerate(
            findings,
            start=1
        ):

            finding_data.append(

                [

                    Paragraph(
                        str(index),
                        small_style
                    ),

                    Paragraph(
                        str(finding),
                        small_style
                    )

                ]

            )


        finding_table = Table(

            finding_data,

            colWidths=[
                20 * mm,
                140 * mm
            ]

        )


        finding_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP"
                ),

                (
                    "PADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )

            ])

        )


        content.append(
            finding_table
        )

    else:

        content.append(

            Paragraph(
                "No suspicious findings were identified.",
                normal_style
            )

        )


    # =====================================================
    # 6. AI / ML ANALYSIS
    # =====================================================

    content.append(

        Paragraph(
            "6. AI / ML Analysis",
            heading_style
        )

    )


    ai_data = [

        [
            Paragraph(
                "<b>Parameter</b>",
                small_style
            ),

            Paragraph(
                "<b>Result</b>",
                small_style
            )
        ],

        [
            Paragraph(
                "AI Classification",
                small_style
            ),

            Paragraph(
                str(ai_status),
                small_style
            )
        ],

        [
            Paragraph(
                "Anomaly Detected",
                small_style
            ),

            Paragraph(
                "Yes" if anomaly else "No",
                small_style
            )
        ],

        [
            Paragraph(
                "AI Score",
                small_style
            ),

            Paragraph(
                str(ai_score),
                small_style
            )
        ]

    ]


    ai_table = Table(

        ai_data,

        colWidths=[
            80 * mm,
            80 * mm
        ]

    )


    ai_table.setStyle(

        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.lightgrey
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),

            (
                "PADDING",
                (0, 0),
                (-1, -1),
                7
            )

        ])

    )


    content.append(
        ai_table
    )


    # =====================================================
    # 7. RECOMMENDATIONS
    # =====================================================

    content.append(

        Paragraph(
            "7. Recommended Actions",
            heading_style
        )

    )


    if risk_level in [
        "Critical",
        "High"
    ]:

        recommendations = [

            "Immediately isolate the affected system if required.",

            "Preserve the original evidence and maintain forensic integrity.",

            "Perform detailed investigation of identified IOCs.",

            "Review relevant system, network and security logs.",

            "Initiate appropriate incident-response procedures."

        ]

    elif risk_level == "Medium":

        recommendations = [

            "Perform additional forensic analysis.",

            "Review identified suspicious indicators.",

            "Monitor the affected system for additional activity.",

            "Preserve relevant evidence for further investigation."

        ]

    else:

        recommendations = [

            "Continue routine security monitoring.",

            "Maintain appropriate evidence and logging practices.",

            "Investigate further if additional suspicious activity is observed."

        ]


    for recommendation in recommendations:

        content.append(

            Paragraph(

                "• " + recommendation,

                normal_style

            )

        )

        content.append(
            Spacer(1, 4)
        )


    # =====================================================
    # 8. CONCLUSION
    # =====================================================

    content.append(

        Paragraph(
            "8. Conclusion",
            heading_style
        )

    )


    conclusion = (

        f"The Cyber Triage Tool analyzed the submitted "
        f"evidence using automated forensic analysis, "
        f"IOC detection, risk assessment and AI/ML-based "
        f"anomaly analysis. The evidence received a risk "
        f"score of <b>{risk_score}/100</b> and was "
        f"classified as <b>{risk_level}</b>. "
        f"The analysis identified "
        f"<b>{total_iocs}</b> indicators of compromise "
        f"and <b>{total_findings}</b> suspicious findings. "
        f"The generated report is intended to support "
        f"forensic investigators in prioritizing evidence "
        f"and making informed investigation decisions."

    )


    content.append(

        Paragraph(
            conclusion,
            normal_style
        )

    )


    # =====================================================
    # 9. DISCLAIMER
    # =====================================================

    content.append(
        Spacer(1, 15)
    )


    content.append(

        Paragraph(

            "<b>Disclaimer:</b> This report is generated "
            "automatically by the Cyber Triage Tool. "
            "The findings should be reviewed and validated "
            "by a qualified digital forensic investigator "
            "before being used for formal investigative, "
            "legal or organizational purposes.",

            small_style

        )

    )


    # =====================================================
    # BUILD DOCUMENT
    # =====================================================

    document.build(

        content,

        onFirstPage=add_page_number,

        onLaterPages=add_page_number

    )


    return report_path