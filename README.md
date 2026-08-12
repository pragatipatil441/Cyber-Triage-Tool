# 🛡️ Cyber Triage Tool

An AI-Assisted Digital Forensic Investigation Platform for analyzing digital evidence and identifying suspicious activities, indicators of compromise (IOCs), and potential security risks.

---

## 📌 Project Overview

The Cyber Triage Tool is a web-based digital forensics application developed using Python and Flask.

It allows investigators to upload digital evidence files, automatically analyze them, calculate a risk score, identify suspicious findings and indicators of compromise, store investigation records, and generate forensic PDF reports.

---

## ✨ Features

- 📁 Digital evidence upload
- 🔍 Automated evidence analysis
- 🚨 Indicator of Compromise (IOC) detection
- ⚠️ Suspicious activity detection
- 🎯 Risk score calculation
- 🛡️ Risk-level classification
- 🤖 AI/ML-based analysis
- 📊 Investigation dashboard
- 📋 Investigation history
- 🔎 Detailed investigation view
- 💾 SQLite database storage
- 📄 PDF forensic report generation
- 🔐 Secure filename handling
- ❌ Invalid file-type validation
- 🧪 Error and input validation

---

## 📂 Supported Evidence Formats

The application currently supports:

- `.txt`
- `.log`
- `.csv`
- `.json`

---

## 🛠️ Technology Stack

### Backend

- Python
- Flask
- SQLite

### Frontend

- HTML5
- CSS3
- Jinja2

### Security / Utilities

- Werkzeug
- Secure filename handling

### Reporting

- PDF report generation

---

## 📁 Project Structure

```text
Cyber_Triage_Tool/
│
├── app.py
├── database.py
├── report_generator.py
│
├── analyzer/
│   ├── __init__.py
│   └── evidence_analyzer.py
│
├── ml/
│
├── templates/
│   ├── dashboard.html
│   ├── results.html
│   ├── history.html
│   ├── investigation.html
│   └── report_success.html
│
├── static/
│
├── screenshots/
│   ├── dashboard.png
│   ├── investigation.png
│   └── investigationhistory.png
│
├── uploads/
├── reports/
│
├── README.md
└── .gitignore