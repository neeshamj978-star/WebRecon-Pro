import os
import re
import json
import uuid
import sqlite3
import threading
from datetime import datetime
from xml.sax.saxutils import escape

from flask import (
    Flask,
    render_template,
    request,
    send_file,
    abort,
    jsonify
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)

from scanner import scan_website, calculate_security_score


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")

DATABASE = os.path.join(BASE_DIR, "webrecon_history.db")

os.makedirs(REPORTS_DIR, exist_ok=True)

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR
)

app.secret_key = os.environ.get(
    "WEBRECON_SECRET_KEY",
    "webrecon-local-development-key-change-before-deployment"
)


# ==========================================
# BACKGROUND SCAN STORAGE
# ==========================================

scan_jobs = {}
scan_jobs_lock = threading.Lock()


def update_scan_job(scan_id, **updates):
    """Safely update the progress information for a scan."""

    with scan_jobs_lock:
        if scan_id in scan_jobs:
            scan_jobs[scan_id].update(updates)


def get_scan_job(scan_id):
    """Return a safe copy of a scan's current status."""

    with scan_jobs_lock:
        job = scan_jobs.get(scan_id)

        if job is None:
            return None

        return dict(job)


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def initialize_database():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                overall_score INTEGER,
                grade TEXT,
                categories TEXT,
                results TEXT,
                recommendations TEXT,
                report_id TEXT
            )
        """)
        db.commit()


# ==========================================
# SAVE SCAN HISTORY
# ==========================================

def save_scan(target, results, score, report_id):

    categories = score.get("categories", {})
    recommendations = score.get("recommendations", [])

    with get_db() as db:
        db.execute("""
            INSERT INTO scans (
                target,
                scanned_at,
                overall_score,
                grade,
                categories,
                results,
                recommendations,
                report_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            target,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            score.get("overall", 0),
            score.get("grade", "N/A"),
            json.dumps(categories),
            json.dumps(results),
            json.dumps(recommendations),
            report_id
        ))

        db.commit()


# ==========================================
# LOAD INDIVIDUAL SCAN
# ==========================================

def get_scan(scan_id):

    with get_db() as db:
        scan = db.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,)
        ).fetchone()

    if not scan:
        return None

    data = dict(scan)

    data["categories"] = json.loads(data["categories"] or "{}")
    data["results"] = json.loads(data["results"] or "[]")
    data["recommendations"] = json.loads(
        data["recommendations"] or "[]"
    )

    return data


# ==========================================
# PDF REPORT GENERATOR
# ==========================================

def create_pdf_report(target, results, score):

    report_id = uuid.uuid4().hex

    report_path = os.path.join(
        REPORTS_DIR,
        f"{report_id}.pdf"
    )

    document = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "WebReconTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=colors.HexColor("#087e8b"),
        spaceAfter=10
    )

    heading_style = ParagraphStyle(
        "WebReconHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#087e8b"),
        spaceBefore=16,
        spaceAfter=8
    )

    normal_style = styles["BodyText"]

    story = []

    story.append(Paragraph("WebRecon Pro", title_style))

    story.append(Paragraph(
        "Website Security &amp; Intelligence Report",
        styles["Heading2"]
    ))

    story.append(Spacer(1, 15))

    story.append(Paragraph(
        f"<b>Target:</b> {escape(str(target))}",
        normal_style
    ))

    story.append(Paragraph(
        f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        normal_style
    ))

    story.append(Paragraph(
        f"<b>Overall Security Score:</b> {score.get('overall', 0)}/100",
        normal_style
    ))

    story.append(Paragraph(
        f"<b>Grade:</b> {escape(str(score.get('grade', 'N/A')))}",
        normal_style
    ))

    story.append(HRFlowable(
        width="100%",
        color=colors.HexColor("#087e8b"),
        thickness=1
    ))

    story.append(Paragraph(
        "Security Category Performance",
        heading_style
    ))

    category_data = [
        ["Category", "Score", "Maximum", "Percentage"]
    ]

    for name, item in score.get("categories", {}).items():
        category_data.append([
            escape(str(name)),
            str(item.get("score", "N/A")),
            str(item.get("max", "N/A")),
            str(item.get("percent", "N/A")) + "%"
        ])

    category_table = Table(
        category_data,
        repeatRows=1,
        colWidths=[2.4 * inch, 0.9 * inch, 0.9 * inch, 1.1 * inch]
    )

    category_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#087e8b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    story.append(category_table)

    story.append(Paragraph(
        "Security Recommendations",
        heading_style
    ))

    recommendations = score.get("recommendations", [])

    if recommendations:
        for recommendation in recommendations:
            story.append(Paragraph(
                "&#8226; " + escape(str(recommendation)),
                normal_style
            ))
            story.append(Spacer(1, 5))
    else:
        story.append(Paragraph(
            "No recommendations were generated.",
            normal_style
        ))

    story.append(Paragraph(
        "Technical Scan Findings",
        heading_style
    ))

    result_data = [
        ["Security Check", "Status", "Details"]
    ]

    for result in results:
        result_data.append([
            escape(str(result.get("name", ""))),
            escape(str(result.get("status", ""))),
            escape(str(result.get("details", "")))[:350]
        ])

    result_table = Table(
        result_data,
        repeatRows=1,
        colWidths=[1.5 * inch, 0.8 * inch, 3.2 * inch]
    )

    result_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#087e8b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    story.append(result_table)

    story.append(Spacer(1, 25))

    story.append(Paragraph(
        "This report contains automated security observations. "
        "It is not a complete penetration test or guarantee of security.",
        normal_style
    ))

    story.append(Spacer(1, 15))

    story.append(Paragraph(
        "<b>Developed by Shawkat Ali</b>",
        normal_style
    ))

    story.append(Paragraph(
        "WebRecon Pro | Educational Cybersecurity Project | 2026",
        normal_style
    ))

    document.build(story)

    return report_id


# ==========================================
# BACKGROUND SCAN WORKER
# ==========================================

def run_scan_in_background(scan_id, target):

    try:
        update_scan_job(
            scan_id,
            status="running",
            stage="Starting website scan",
            progress=1
        )

        def progress_callback(stage, percent):
            # Reserve the final progress range for scoring and reporting.
            display_percent = min(94, int(percent * 0.92))

            update_scan_job(
                scan_id,
                stage=stage,
                progress=display_percent
            )

        # Run the real website scanner.
        results = scan_website(
            target,
            progress_callback=progress_callback
        )

        update_scan_job(
            scan_id,
            stage="Calculating security score",
            progress=95
        )

        score = calculate_security_score(results)

        update_scan_job(
            scan_id,
            stage="Generating PDF security report",
            progress=97
        )

        report_id = create_pdf_report(
            target,
            results,
            score
        )

        update_scan_job(
            scan_id,
            stage="Saving scan history",
            progress=99
        )

        save_scan(
            target,
            results,
            score,
            report_id
        )

        update_scan_job(
            scan_id,
            status="completed",
            stage="Scan completed successfully",
            progress=100,
            results=results,
            score=score,
            report_id=report_id,
            error=None
        )

    except Exception:
        app.logger.exception("Background scan failed")

        update_scan_job(
            scan_id,
            status="failed",
            stage="Scan failed",
            error="The scan could not be completed. Check the Flask terminal for details."
        )


# ==========================================
# DASHBOARD CATEGORY PREPARATION
# ==========================================

def prepare_display_categories(score):

    display_categories = []

    for name, item in score.get("categories", {}).items():

        category_score = item.get("score")
        maximum = item.get("max", 0)
        percent = item.get("percent")

        if category_score is None:
            status = "Not available"
        else:
            status = f"{percent}% of available points"

        display_categories.append({
            "name": name,
            "score": category_score,
            "maximum": maximum,
            "status": status
        })

    return display_categories


def render_dashboard(
    target="",
    results=None,
    score=None,
    report_id="",
    error="",
    scan_id=""
):

    results = results or []

    display_categories = (
        prepare_display_categories(score)
        if score else []
    )

    return render_template(
        "index.html",
        results=results,
        target=target,
        error=error,
        report_id=report_id,
        score=score,
        security_score=score,
        display_categories=display_categories,
        scan_id=scan_id
    )


# ==========================================
# MAIN DASHBOARD
# ==========================================

@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        target = request.form.get("target", "").strip()

        if not target:
            return render_dashboard(
                error="Please enter a domain or IP address."
            )

        # Create a unique ID for this scan.
        scan_id = uuid.uuid4().hex

        with scan_jobs_lock:
            scan_jobs[scan_id] = {
                "status": "queued",
                "stage": "Waiting for scan to start",
                "progress": 0,
                "target": target,
                "error": None,
                "results": None,
                "score": None,
                "report_id": None
            }

        # Run the scan separately so the browser can poll for progress.
        worker = threading.Thread(
            target=run_scan_in_background,
            args=(scan_id, target),
            daemon=True
        )

        worker.start()

        return render_dashboard(
            target=target,
            scan_id=scan_id
        )

    return render_dashboard(
        target=request.args.get("target", "")
    )


# ==========================================
# LIVE PROGRESS API
# ==========================================

@app.route("/progress/<scan_id>")
def scan_progress(scan_id):

    if not re.fullmatch(r"[a-f0-9]{32}", scan_id):
        abort(404)

    job = get_scan_job(scan_id)

    if job is None:
        return jsonify({
            "status": "not_found",
            "error": "Scan session not found. It may have expired after a server restart."
        }), 404

    # Do not send full scan findings through the polling endpoint.
    return jsonify({
        "status": job["status"],
        "stage": job["stage"],
        "progress": job["progress"],
        "error": job["error"]
    })


# ==========================================
# DISPLAY COMPLETED SCAN
# ==========================================

@app.route("/scan-result/<scan_id>")
def scan_result(scan_id):

    if not re.fullmatch(r"[a-f0-9]{32}", scan_id):
        abort(404)

    job = get_scan_job(scan_id)

    if job is None or job.get("status") != "completed":
        abort(404)

    return render_dashboard(
        target=job["target"],
        results=job["results"],
        score=job["score"],
        report_id=job["report_id"],
        scan_id=scan_id
    )


# ==========================================
# SCAN HISTORY
# ==========================================

@app.route("/history")
def history():

    with get_db() as db:
        scans = db.execute("""
            SELECT
                id,
                target,
                scanned_at,
                overall_score,
                grade,
                report_id
            FROM scans
            ORDER BY id DESC
        """).fetchall()

    return render_template(
        "history.html",
        scans=scans
    )


# ==========================================
# COMPARE REPORTS
# ==========================================

@app.route("/compare", methods=["GET", "POST"])
def compare():

    with get_db() as db:
        scans = db.execute("""
            SELECT
                id,
                target,
                scanned_at,
                overall_score,
                grade
            FROM scans
            ORDER BY id DESC
        """).fetchall()

    first = None
    second = None
    comparison = None
    error = ""

    if request.method == "POST":

        try:
            first_id = int(request.form.get("scan_one", ""))
            second_id = int(request.form.get("scan_two", ""))

            if first_id == second_id:
                raise ValueError("Choose two different scans.")

            first = get_scan(first_id)
            second = get_scan(second_id)

            if not first or not second:
                raise ValueError("Selected scans do not exist.")

            first_target = first["target"].lower().rstrip("/")
            second_target = second["target"].lower().rstrip("/")

            if first_target != second_target:
                raise ValueError(
                    "Select scans of the same website."
                )

            score_change = (
                second["overall_score"] - first["overall_score"]
            )

            category_changes = []

            for category, old in first["categories"].items():

                new = second["categories"].get(category, {})

                old_score = old.get("score")
                new_score = new.get("score")

                if old_score is not None and new_score is not None:
                    change = new_score - old_score
                else:
                    change = None

                category_changes.append({
                    "name": category,
                    "old": old_score,
                    "new": new_score,
                    "change": change
                })

            comparison = {
                "score_change": score_change,
                "category_changes": category_changes
            }

        except (ValueError, TypeError):

            error = (
                "Please select two different valid scans "
                "of the same website."
            )

    return render_template(
        "compare.html",
        scans=scans,
        first=first,
        second=second,
        comparison=comparison,
        error=error
    )


# ==========================================
# PDF DOWNLOAD
# ==========================================

@app.route("/download/<report_id>")
def download_report(report_id):

    if not re.fullmatch(r"[a-f0-9]{32}", report_id):
        abort(404)

    report_path = os.path.join(
        REPORTS_DIR,
        f"{report_id}.pdf"
    )

    if not os.path.isfile(report_path):
        abort(404)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"WebRecon_Report_{report_id[:8]}.pdf",
        mimetype="application/pdf"
    )


# ==========================================
# START APPLICATION
# ==========================================

initialize_database()


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )

