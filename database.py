import sqlite3
from datetime import datetime


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

DATABASE = "cyber_triage.db"


# =========================================================
# CREATE DATABASE AND TABLE
# =========================================================

def create_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            filename TEXT NOT NULL,

            upload_time TEXT NOT NULL,

            risk_score INTEGER,

            risk_level TEXT,

            total_iocs INTEGER,

            suspicious_findings INTEGER

        )
    """)

    connection.commit()

    connection.close()


# =========================================================
# SAVE INVESTIGATION
# =========================================================

def save_investigation(
    filename,
    risk_score,
    risk_level,
    total_iocs,
    suspicious_findings
):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    upload_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO investigations
        (
            filename,
            upload_time,
            risk_score,
            risk_level,
            total_iocs,
            suspicious_findings
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        filename,
        upload_time,
        risk_score,
        risk_level,
        total_iocs,
        suspicious_findings
    ))

    # Get the ID created by SQLite
    investigation_id = cursor.lastrowid

    connection.commit()

    connection.close()

    return investigation_id


# =========================================================
# GET DASHBOARD STATISTICS
# =========================================================

def get_dashboard_statistics():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM investigations
    """)

    total_evidence = cursor.fetchone()[0]


    cursor.execute("""
        SELECT COALESCE(
            SUM(suspicious_findings),
            0
        )
        FROM investigations
    """)

    suspicious_artifacts = cursor.fetchone()[0]


    cursor.execute("""
        SELECT COALESCE(
            SUM(total_iocs),
            0
        )
        FROM investigations
    """)

    detected_iocs = cursor.fetchone()[0]


    cursor.execute("""
        SELECT COUNT(*)
        FROM investigations
        WHERE risk_level = 'Critical'
    """)

    critical_findings = cursor.fetchone()[0]


    connection.close()


    return {

        "total_evidence": total_evidence,

        "suspicious_artifacts": suspicious_artifacts,

        "detected_iocs": detected_iocs,

        "critical_findings": critical_findings

    }


# =========================================================
# GET ALL INVESTIGATIONS
# =========================================================

def get_all_investigations():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            filename,
            upload_time,
            risk_score,
            risk_level,
            total_iocs,
            suspicious_findings
        FROM investigations
        ORDER BY id DESC
    """)

    investigations = cursor.fetchall()

    connection.close()

    return investigations


# =========================================================
# GET SINGLE INVESTIGATION
# =========================================================

def get_investigation_by_id(investigation_id):

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            filename,
            upload_time,
            risk_score,
            risk_level,
            total_iocs,
            suspicious_findings
        FROM investigations
        WHERE id = ?
    """, (investigation_id,))

    investigation = cursor.fetchone()

    connection.close()

    return investigation


# =========================================================
# GET RISK DISTRIBUTION
# =========================================================

def get_risk_distribution():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            risk_level,
            COUNT(*)
        FROM investigations
        GROUP BY risk_level
    """)

    rows = cursor.fetchall()

    connection.close()


    distribution = {

        "Low": 0,

        "Medium": 0,

        "High": 0,

        "Critical": 0

    }


    for risk_level, count in rows:

        if risk_level in distribution:

            distribution[risk_level] = count


    return distribution


# =========================================================
# GET AI / ML STATISTICS
# =========================================================

def get_ai_statistics():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()


    cursor.execute("""
        SELECT COUNT(*)
        FROM investigations
        WHERE risk_level IN ('High', 'Critical')
    """)

    anomalous = cursor.fetchone()[0]


    cursor.execute("""
        SELECT COUNT(*)
        FROM investigations
        WHERE risk_level IN ('Low', 'Medium')
    """)

    normal = cursor.fetchone()[0]


    connection.close()


    return {

        "normal": normal,

        "anomalous": anomalous

    }


# =========================================================
# GET RECENT INVESTIGATIONS
# =========================================================

def get_recent_investigations(limit=5):

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            filename,
            upload_time,
            risk_score,
            risk_level,
            total_iocs,
            suspicious_findings
        FROM investigations
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    investigations = cursor.fetchall()

    connection.close()

    return investigations