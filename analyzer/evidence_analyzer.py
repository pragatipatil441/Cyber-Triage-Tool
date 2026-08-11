import re

from ml.anomaly_detector import detect_anomaly


# ---------------------------------------------------
# EXTRACT IP ADDRESSES
# ---------------------------------------------------

def extract_ips(text):

    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    return list(
        set(
            re.findall(
                pattern,
                text
            )
        )
    )


# ---------------------------------------------------
# EXTRACT URLs
# ---------------------------------------------------

def extract_urls(text):

    pattern = r'https?://[^\s]+'

    return list(
        set(
            re.findall(
                pattern,
                text
            )
        )
    )


# ---------------------------------------------------
# EXTRACT EMAIL ADDRESSES
# ---------------------------------------------------

def extract_emails(text):

    pattern = (
        r'\b[A-Za-z0-9._%+-]+'
        r'@[A-Za-z0-9.-]+'
        r'\.[A-Za-z]{2,}\b'
    )

    return list(
        set(
            re.findall(
                pattern,
                text
            )
        )
    )


# ---------------------------------------------------
# EXTRACT HASHES
# ---------------------------------------------------

def extract_hashes(text):

    pattern = (
        r'\b(?:'
        r'[a-fA-F0-9]{32}|'
        r'[a-fA-F0-9]{40}|'
        r'[a-fA-F0-9]{64}'
        r')\b'
    )

    return list(
        set(
            re.findall(
                pattern,
                text
            )
        )
    )


# ---------------------------------------------------
# DETECT SUSPICIOUS KEYWORDS
# ---------------------------------------------------

def detect_suspicious_keywords(text):

    keywords = [

        "malware",

        "ransomware",

        "phishing",

        "trojan",

        "keylogger",

        "backdoor",

        "unauthorized",

        "suspicious",

        "failed login",

        "brute force",

        "exploit",

        "attack",

        "malicious"

    ]


    text_lower = text.lower()

    detected = []


    for keyword in keywords:

        if keyword in text_lower:

            detected.append(
                keyword
            )


    return detected


# ---------------------------------------------------
# CALCULATE RISK SCORE
# ---------------------------------------------------

def calculate_risk(
    ips,
    urls,
    hashes,
    keywords
):

    score = 0


    # IP = 10 points

    score += len(ips) * 10


    # URL = 15 points

    score += len(urls) * 15


    # Hash = 20 points

    score += len(hashes) * 20


    # Suspicious keyword = 10 points

    score += len(keywords) * 10


    # Maximum score = 100

    score = min(
        score,
        100
    )


    # Risk level

    if score >= 80:

        level = "Critical"

    elif score >= 60:

        level = "High"

    elif score >= 30:

        level = "Medium"

    else:

        level = "Low"


    return score, level


# ---------------------------------------------------
# MAIN EVIDENCE ANALYSIS
# ---------------------------------------------------

def analyze_evidence(file_path):


    # -----------------------------------------------
    # READ FILE
    # -----------------------------------------------

    with open(

        file_path,

        "r",

        encoding="utf-8",

        errors="ignore"

    ) as file:

        text = file.read()


    # -----------------------------------------------
    # EXTRACT FORENSIC INFORMATION
    # -----------------------------------------------

    ips = extract_ips(text)

    urls = extract_urls(text)

    emails = extract_emails(text)

    hashes = extract_hashes(text)

    keywords = detect_suspicious_keywords(
        text
    )


    # -----------------------------------------------
    # CALCULATE RISK
    # -----------------------------------------------

    risk_score, risk_level = calculate_risk(

        ips,

        urls,

        hashes,

        keywords

    )


    # -----------------------------------------------
    # AI / ML ANOMALY DETECTION
    # -----------------------------------------------

    ml_result = detect_anomaly(

        ips,

        urls,

        hashes,

        keywords

    )


    # -----------------------------------------------
    # TOTAL IOC COUNT
    # -----------------------------------------------

    total_iocs = (

        len(ips)

        + len(urls)

        + len(hashes)

    )


    # -----------------------------------------------
    # RETURN COMPLETE RESULTS
    # -----------------------------------------------

    return {

        "ips": ips,

        "urls": urls,

        "emails": emails,

        "hashes": hashes,

        "keywords": keywords,

        "risk_score": risk_score,

        "risk_level": risk_level,

        "total_iocs": total_iocs,

        "total_findings": len(keywords),

        # AI/ML results

        "ml_anomaly": ml_result["anomaly"],

        "ml_status": ml_result["status"],

        "ml_score": ml_result["score"]

    }