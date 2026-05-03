# Network Traffic Analyzer & Basic IDS 🛡️

A command-line based Network Traffic Analyzer and rudimentary Intrusion Detection System (IDS) written in Python. This tool leverages the `scapy` library to sniff network packets in real-time, inspect payloads, detect specific network anomalies, and generate visually rich terminal reports.

## 🌟 Features

* **Real-Time Packet Sniffing:** Captures and analyzes IP traffic (TCP, UDP, ICMP) across specified network interfaces.
* **HTTP Credential Harvester:** Inspects unencrypted HTTP traffic to detect and extract potential plaintext credentials (usernames, passwords, login payloads).
* **Intrusion Detection System (IDS):** Automatically monitors for and detects network anomalies such as **TCP SYN Scans** (Stealth Scans) often used in the reconnaissance phase of cyber attacks.
* **Automated Threat Logging:** Suspicious activities and extracted credentials are automatically logged with timestamps into a `security_alerts.log` file for incident response analysis.
* **Advanced CLI Dashboard:** Features a beautifully colored terminal output using ANSI escape codes, providing a post-capture summary that includes:
  * Overall Capture Summary (Duration, Total Packets, Average Bandwidth).
  * Protocol Distribution Table.
  * "Top 10 Talkers" Table (identifying endpoints sending/receiving the most data).

## 📸 Screenshot

*(Catatan untuk Anda: Anda bisa mengunggah file `capture.png` Anda ke GitHub, lalu ganti teks ini dengan sintaks gambar Markdown, contoh: `![CLI Dashboard](capture.png)`)*

## 🛠️ Prerequisites

To run this tool, you need to have Python installed along with the `scapy` library. A Linux-based environment (like Kali Linux or Ubuntu) is highly recommended.
```bash
pip install scapy argparse
