# PhishPhry – Advanced Phishing URL Analyzer

**PhishPhry** is a powerful open-source phishing investigation tool designed for cybersecurity professionals, analysts, and penetration testers. It provides a full-featured GUI for analyzing suspicious URLs, previewing their content, scanning with real-time threat intelligence APIs, and generating detailed HTML reports — all in one Python-based application.

---

## 🚀 Features

- 🧭 Live website rendering in a secure embedded browser (PyQt6)
- 🔍 WHOIS, DNS, and SSL certificate information lookup
- 🧪 HTML source inspection with keyword and redirect chain scanning
- 📍 IP geolocation from multiple DNS sources
- 🧠 Heuristic analysis for phishing indicators
- 🛡️ Threat intelligence via **VirusTotal** and **AbuseIPDB** APIs
- 📄 Exportable HTML reports for documentation and response

---

## 🛠️ Installation

Clone the repository and run the provided setup script:


## git clone https://github.com/jamaldoTS/PhishPhry.git
## cd PhishPhry
## chmod +x install.sh
## ./install.sh

This will: 

Create a virtual environment (phishphry-env)
Install all required Python dependencies

--------------

▶️ UsageAfter installation:

## chmod +x run.sh
## ./run.sh

> 📝 Note: You must activate the virtual environment before each use.

----------------

🔐 Threat Intelligence Setup

To use threat intelligence features, obtain free API keys from:

VirusTotal : https://www.virustotal.com/

AbuseIPDB : https://www.abuseipdb.com/

------------

Paste them into the "Threat Intelligence" tab inside the application.

🧪 Use Cases

SOC/Blue Team phishing investigations

Threat hunting and IOC validation

OSINT and forensics

Red Team phishing site recon



--------------

📬 Support

Need help or want to report an issue?
📧 Contact: turbineshield@gmail.com


---------------

📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

