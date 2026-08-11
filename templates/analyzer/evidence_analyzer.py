import re


def extract_ips(text):
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return list(set(re.findall(pattern, text)))


def extract_urls(text):
    pattern = r'https?://[^\s]+'
    return list(set(re.findall(pattern, text)))


def extract_emails(text):
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    return list(set(re.findall(pattern, text)))


def extract_hashes(text):
    pattern = r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b'
    return list(set(re.findall(pattern, text)))


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
            detected.append(keyword)

    return detected


def calculate_risk(ips, urls, hashes, keywords):

    score = 0

    score += len(ips) * 10
    score += len(urls) * 15
    score += len(hashes) * 20
    score += len(keywords) * 10

    score = min(score, 100)

    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return score, level


def analyze_evidence(file_path):

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        text = file.read()

    ips = extract_ips(text)
    urls = extract_urls(text)
    emails = extract_emails(text)
    hashes = extract_hashes(text)
    keywords = detect_suspicious_keywords(text)

    score, level = calculate_risk(
        ips,
        urls,
        hashes,
        keywords
    )

    return {
        "ips": ips,
        "urls": urls,
        "emails": emails,
        "hashes": hashes,
        "keywords": keywords,
        "risk_score": score,
        "risk_level": level,
        "total_iocs": len(ips) + len(urls) + len(hashes),
        "total_findings": len(keywords)
    }