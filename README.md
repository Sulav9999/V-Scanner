# V-Scanner

# 🔐 Custom Vulnerability Scanner - V_Scanner

V-Scanner is a lightweight, modular vulnerability scanning system designed for small-scale environments, cybersecurity students, and ethical hacking learners. Built entirely in Python, it offers functionality similar to tools like Nmap and Nessus, but without external dependencies or complex setup.

The system includes four main components:
1. **Network & Port Scanner** – Discovers live devices using ARP and performs TCP port scans using native socket programming.
2. **Vulnerability Scanner** – Grabs service banners and matches them with real-time CVE data from the National Vulnerability Database (NVD) via API.
3. **Credential Breach Checker** – Scans credentials against locally stored breach data to simulate online data leak checks without risking privacy.
4. **PDF Report Generator** – Compiles all results into a professional, structured PDF report using ReportLab.

This project was created as part of a Final Year Research Project, using Agile with Scrum methodology, and includes complete modular architecture, testing, and documentation. All results are stored in JSON and compiled in a readable format for review and archiving.

> 🧠 Ideal for cybersecurity education, penetration testing practice, and offline vulnerability assessments.

## ✅ Features
- Real-time port and host discovery (no Nmap required)
- CVE vulnerability detection and CVSS scoring
- Local credential leak verification
- Professional PDF reporting
- CLI-based, fully open source, and customizable

## 📂 Structure
- `/network_portscanner.py` – Network scanner
- `/vulnerability_scanner.py` – CVE matcher
- `/credential_checker.py` – Breach detector
- `/report_generator.py` – PDF creator
- `/main.py` – Main controller
- `/reports/` – Output directory

## 📌 Requirements
- Python 3.8+
- `reportlab`, `scapy`, `requests`, `tabulate`, `psutil`

## 🚀 Getting Started
1. Clone the repository
2. Install the dependencies (`pip install -r requirements.txt`)
3. Run each module or use `main.py` for full workflow
4. Check `reports/` folder for JSON & PDF outputs

## 📄 License
This project is licensed under the MIT License.

