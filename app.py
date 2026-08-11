from flask import (
    Flask,
    render_template,
    request,
    send_from_directory
)

import os

from werkzeug.utils import secure_filename

from analyzer.evidence_analyzer import analyze_evidence

from database import (
    create_database,
    save_investigation,
    get_dashboard_statistics,
    get_all_investigations,
    get_risk_distribution,
    get_ai_statistics,
    get_recent_investigations,
    get_investigation_by_id
)

from report_generator import generate_pdf_report


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)


# =========================================================
# FOLDER CONFIGURATION
# =========================================================

UPLOAD_FOLDER = "uploads"

REPORT_FOLDER = "reports"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

app.config["REPORT_FOLDER"] = REPORT_FOLDER


# =========================================================
# CREATE REQUIRED FOLDERS
# =========================================================

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    REPORT_FOLDER,
    exist_ok=True
)


# =========================================================
# ALLOWED FILE TYPES
# =========================================================

ALLOWED_EXTENSIONS = {
    "txt",
    "log",
    "csv",
    "json"
}


def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(
            ".",
            1
        )[1].lower()
        in ALLOWED_EXTENSIONS
    )


# =========================================================
# CREATE DATABASE
# =========================================================

create_database()


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def home():

    statistics = get_dashboard_statistics()

    risk_distribution = get_risk_distribution()

    ai_statistics = get_ai_statistics()

    recent_investigations = get_recent_investigations(5)

    return render_template(

        "dashboard.html",

        total_evidence=
            statistics["total_evidence"],

        suspicious_artifacts=
            statistics["suspicious_artifacts"],

        detected_iocs=
            statistics["detected_iocs"],

        critical_findings=
            statistics["critical_findings"],

        risk_distribution=
            risk_distribution,

        ai_statistics=
            ai_statistics,

        recent_investigations=
            recent_investigations

    )


# =========================================================
# UPLOAD EVIDENCE
# =========================================================

@app.route(
    "/upload",
    methods=["POST"]
)
def upload_file():

    # -----------------------------------------------------
    # Check uploaded file
    # -----------------------------------------------------

    if "evidence" not in request.files:

        return "No evidence file selected."


    file = request.files["evidence"]


    # -----------------------------------------------------
    # Check filename
    # -----------------------------------------------------

    if file.filename == "":

        return "No evidence file selected."


    # -----------------------------------------------------
    # Check extension
    # -----------------------------------------------------

    if not allowed_file(file.filename):

        return (
            "Invalid file type. "
            "Please upload TXT, LOG, CSV or JSON."
        )


    # -----------------------------------------------------
    # Secure filename
    # -----------------------------------------------------

    filename = secure_filename(
        file.filename
    )


    # -----------------------------------------------------
    # File path
    # -----------------------------------------------------

    file_path = os.path.join(

        app.config["UPLOAD_FOLDER"],

        filename

    )


    # -----------------------------------------------------
    # Save evidence
    # -----------------------------------------------------

    file.save(file_path)


    # =====================================================
    # ANALYZE EVIDENCE
    # =====================================================

    results = analyze_evidence(
        file_path
    )


    # =====================================================
    # SAVE TO DATABASE
    # =====================================================

    investigation_id = save_investigation(

        filename,

        results["risk_score"],

        results["risk_level"],

        results["total_iocs"],

        results["total_findings"]

    )


    # =====================================================
    # GET THE EXACT SAVED RECORD
    # =====================================================

    investigation = get_investigation_by_id(
        investigation_id
    )


    # -----------------------------------------------------
    # Safety check
    # -----------------------------------------------------

    if investigation is None:

        return (
            "Investigation was saved, "
            "but could not be retrieved.",
            500
        )


    # =====================================================
    # SHOW RESULTS
    # =====================================================

    return render_template(

        "results.html",

        filename=filename,

        results=results,

        investigation=investigation

    )


# =========================================================
# INVESTIGATION HISTORY
# =========================================================

@app.route("/history")
def history():

    investigations = get_all_investigations()

    return render_template(

        "history.html",

        investigations=investigations

    )


# =========================================================
# VIEW INVESTIGATION
# =========================================================

@app.route(
    "/investigation/<int:investigation_id>"
)
def view_investigation(investigation_id):

    investigation = get_investigation_by_id(
        investigation_id
    )


    if investigation is None:

        return (
            "Investigation not found.",
            404
        )


    return render_template(

        "investigation.html",

        investigation=investigation

    )


# =========================================================
# GENERATE PDF REPORT
# =========================================================

@app.route(
    "/generate-report/<filename>"
)
def generate_report(filename):

    file_path = os.path.join(

        app.config["UPLOAD_FOLDER"],

        filename

    )


    if not os.path.exists(file_path):

        return "Evidence file not found."


    results = analyze_evidence(
        file_path
    )


    report_path = generate_pdf_report(

        filename,

        results

    )


    report_filename = os.path.basename(
        report_path
    )


    report_url = (
        "/reports/"
        + report_filename
    )


    return render_template(

        "report_success.html",

        report_url=report_url,

        filename=filename

    )


# =========================================================
# SERVE PDF REPORTS
# =========================================================

@app.route(
    "/reports/<filename>"
)
def serve_report(filename):

    return send_from_directory(

        app.config["REPORT_FOLDER"],

        filename

    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )