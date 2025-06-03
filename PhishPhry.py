import os
import sys
import socket
import ssl
import datetime
import whois
import requests
import re
import dns.resolver
import base64
import subprocess
from urllib.parse import urlparse
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QTabWidget,
    QTextEdit, QLabel, QMessageBox, QFileDialog, QSpacerItem, QSizePolicy, QGroupBox, QFormLayout
)
from PyQt6.QtWebEngineWidgets import QWebEngineView


class PhishPhryApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PhishPhry - Advanced Phishing URL Inspector")
        self.resize(1150, 800)

        main_layout = QVBoxLayout(self)

        # Top Bar
        top_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL (e.g. https://phishphry.com)")
        self.go_button = QPushButton("Inspect")
        self.go_button.clicked.connect(self.inspect_url)
        self.back_button = QPushButton("Back")
        self.back_button.clicked.connect(self.handle_back)
        top_layout.addWidget(QLabel("URL:"))
        top_layout.addWidget(self.url_input)
        top_layout.addWidget(self.go_button)
        top_layout.addWidget(self.back_button)
        main_layout.addLayout(top_layout)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.web_view = QWebEngineView()
        self.live_tab = self.create_tab_with_widget(self.web_view)
        self.tabs.addTab(self.live_tab, "Live Website")

        self.inspect_text = QTextEdit()
        self.inspect_tab = self.create_tab_with_widget(self.inspect_text)
        self.tabs.addTab(self.inspect_tab, "Inspection")

        self.source_text = QTextEdit()
        self.source_tab = self.create_tab_with_widget(self.source_text)
        self.tabs.addTab(self.source_tab, "Source")

        self.report_text = QTextEdit()
        self.report_tab = QWidget()
        report_layout = QVBoxLayout()
        report_layout.addWidget(self.report_text)
        export_button = QPushButton("Save Report as HTML")
        export_button.clicked.connect(self.save_report)
        report_layout.addWidget(export_button)
        self.report_tab.setLayout(report_layout)
        self.tabs.addTab(self.report_tab, "Report")

        # Threat Intelligence (5th Tab)
        self.threat_tab = QWidget()
        threat_layout = QVBoxLayout()

        api_box = QGroupBox("Threat Intelligence API Keys")
        api_layout = QFormLayout()

        self.abuseipdb_key_input = QLineEdit()
        self.abuseipdb_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.virustotal_key_input = QLineEdit()
        self.virustotal_key_input.setEchoMode(QLineEdit.EchoMode.Password)

        api_layout.addRow("AbuseIPDB Key:", self.abuseipdb_key_input)
        api_layout.addRow("VirusTotal Key:", self.virustotal_key_input)
        api_box.setLayout(api_layout)

        threat_input_layout = QHBoxLayout()
        self.threat_ip_input = QLineEdit()
        self.threat_ip_input.setPlaceholderText("Enter IP")
        self.threat_url_input = QLineEdit()
        self.threat_url_input.setPlaceholderText("Enter URL")
        self.threat_button = QPushButton("Scan Threat Intelligence")
        self.threat_button.clicked.connect(self.run_threat_intel)
        threat_input_layout.addWidget(self.threat_ip_input)
        threat_input_layout.addWidget(self.threat_url_input)
        threat_input_layout.addWidget(self.threat_button)

        self.threat_text = QTextEdit()

        threat_layout.addWidget(api_box)
        threat_layout.addLayout(threat_input_layout)
        threat_layout.addWidget(self.threat_text)
        self.threat_tab.setLayout(threat_layout)
        self.tabs.addTab(self.threat_tab, "Threat Intelligence")

        # Footer with Centered Label
        bottom_layout = QHBoxLayout()
        support_button = QPushButton("Support")
        support_button.setStyleSheet("background-color: red; color: white;")
        support_button.clicked.connect(self.show_support_email)

        bottom_layout.addWidget(support_button)
        bottom_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        footer_label = QLabel("Created by Jamal Mohamed – Turbine Shield Technologies")
        footer_label.setStyleSheet("font-weight: bold;")
        bottom_layout.addWidget(footer_label)

        bottom_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        main_layout.addLayout(bottom_layout)

    def create_tab_with_widget(self, widget):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(widget)
        tab.setLayout(layout)
        return tab

    def handle_back(self):
        self.web_view.back()

    def show_support_email(self):
        QGuiApplication.clipboard().setText("turbineshield@gmail.com")
        QMessageBox.information(self, "Copied", "Support email copied to clipboard.")

    def save_report(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Report", "phishing_report.html", "HTML Files (*.html)")
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("<pre>" + self.report_text.toPlainText() + "</pre>")

    def ssl_info(self, hostname):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                return (
                    f"SSL Certificate:\n"
                    f"  Issuer: {cert.get('issuer')}\n"
                    f"  Subject: {cert.get('subject')}\n"
                    f"  Valid From: {cert.get('notBefore')}\n"
                    f"  Expiry: {cert.get('notAfter')}\n"
                )
        except Exception as e:
            return f"SSL Certificate Error: {e}\n"

    def url_heuristics(self, url):
        parsed = urlparse(url)
        score = 0
        flags = []
        if len(url) > 75:
            score += 1
            flags.append("Long URL")
        if re.search(r'@|%|-|\d{5,}', url):
            score += 1
            flags.append("Suspicious characters")
        if re.match(r'^\d+.\d+.\d+.\d+$', parsed.hostname or ''):
            score += 1
            flags.append("IP used instead of domain")
        return f"URL Heuristics:\n  Risk Score: {score}/3\n  Flags: {', '.join(flags) if flags else 'None'}\n"

    def get_dns_records(self, domain):
        output = "DNS Records:\n"
        try:
            for qtype in ["MX", "TXT", "NS"]:
                answers = dns.resolver.resolve(domain, qtype, lifetime=5)
                output += f"  {qtype}: {[str(r) for r in answers]}\n"
        except Exception as e:
            output += f"  DNS Error: {e}\n"
        return output

    def scan_keywords(self, html):
        keywords = ["login", "verify", "secure", "password", "bank", "update"]
        found = [k for k in keywords if k.lower() in html.lower()]
        return f"Suspicious Content Keywords: {', '.join(found) if found else 'None'}\n"

    def get_redirect_chain(self, url):
        try:
            session = requests.Session()
            resp = session.get(url, allow_redirects=True, timeout=10)
            chain = "Redirect Chain:\n"
            for r in resp.history:
                chain += f"  {r.status_code} -> {r.url}\n"
            chain += f"  {resp.status_code} -> {resp.url}\n"
            return chain
        except Exception as e:
            return f"Redirect Error: {e}\n"

    def run_threat_intel(self):
        ip = self.threat_ip_input.text().strip()
        url = self.threat_url_input.text().strip()
        abuse_key = self.abuseipdb_key_input.text().strip()
        vt_key = self.virustotal_key_input.text().strip()

        output = "=== Threat Intelligence Report ===\n"

        if ip and abuse_key:
            try:
                resp = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    timeout=10
                )
                if resp.ok:
                    data = resp.json()["data"]
                    output += (
                        f"\n--- AbuseIPDB for {ip} ---\n"
                        f"Score: {data['abuseConfidenceScore']}\n"
                        f"Country: {data['countryCode']}\n"
                        f"ISP: {data['isp']}\n"
                        f"Domain: {data['domain']}\n"
                    )
                else:
                    output += f"AbuseIPDB Error: {resp.text}\n"
            except Exception as e:
                output += f"AbuseIPDB Exception: {e}\n"

        if url and vt_key:
            try:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": vt_key},
                    timeout=10
                )
                if resp.ok:
                    data = resp.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    output += (
                        f"\n--- VirusTotal for {url} ---\n"
                        f"Harmless: {stats['harmless']}\n"
                        f"Malicious: {stats['malicious']}\n"
                        f"Suspicious: {stats['suspicious']}\n"
                        f"Undetected: {stats['undetected']}\n"
                    )
                else:
                    output += f"VirusTotal Error: {resp.text}\n"
            except Exception as e:
                output += f"VirusTotal Exception: {e}\n"

        if url:
            try:
                headers = subprocess.check_output(["curl", "-I", url], timeout=10).decode()
                output += f"\n--- curl -I Output ---\n{headers}\n"
            except Exception as e:
                output += f"\nCurl Error: {e}\n"

        self.threat_text.setPlainText(output)

    def get_all_dns_ips(self, domain):
        dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
        all_ips = set()

        for server in dns_servers:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            for record_type in ['A', 'AAAA']:
                try:
                    answers = resolver.resolve(domain, record_type, lifetime=3)
                    for rdata in answers:
                        all_ips.add(rdata.to_text())
                except Exception:
                    pass
        return sorted(all_ips)

    def inspect_url(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a valid URL.")
            return

        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url

        qurl = QUrl(url)
        if not qurl.isValid():
            QMessageBox.warning(self, "URL Error", "Invalid URL entered.")
            return

        self.web_view.load(qurl)
        hostname = qurl.host()

        ip_addresses = self.get_all_dns_ips(hostname)
        if not ip_addresses:
            ip_addresses = ["Unknown"]

        geo_info = ""
        for ip in ip_addresses:
            try:
                geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
                geo_info += (
                    f"IP: {ip}\n"
                    f"  Country: {geo.get('country', 'N/A')}\n"
                    f"  City: {geo.get('city', 'N/A')}\n"
                    f"  ISP: {geo.get('isp', 'N/A')}\n\n"
                )
            except Exception:
                geo_info += f"IP: {ip}\n  Geo lookup failed.\n\n"

        inspect_info = f"Hostname: {hostname}\nIPs found: {len(ip_addresses)}\n\n{geo_info}"
        self.inspect_text.setPlainText(inspect_info)

        try:
            r = requests.get(url, headers={"User-Agent": "PhishPhryBot/1.0"}, timeout=15)
            r.raise_for_status()
            html = r.text
            self.source_text.setPlainText(html)
        except Exception as e:
            html = ""
            self.source_text.setPlainText(f"Fetch failed: {e}")

        report = "=== WHOIS ===\n"
        try:
            w = whois.whois(hostname)
            for k, v in w.items():
                report += f"{k}: {v}\n"
        except Exception as e:
            report += f"WHOIS error: {e}\n"

        report += "\n=== SSL Info ===\n" + self.ssl_info(hostname)
        report += "\n=== Heuristics ===\n" + self.url_heuristics(url)
        report += "\n=== DNS Records ===\n" + self.get_dns_records(hostname)
        report += "\n=== Redirects ===\n" + self.get_redirect_chain(url)
        report += "\n=== Content Scan ===\n" + self.scan_keywords(html)

        self.report_text.setPlainText(report)


if __name__ == '__main__':
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        os.environ['QTWEBENGINE_CHROMIUM_FLAGS'] = '--no-sandbox'

    app = QApplication(sys.argv)
    window = PhishPhryApp()
    window.show()
    sys.exit(app.exec())
