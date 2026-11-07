# 🚀 Go-Log-Hunter: SSH Brute-Force & Auth Log Analyzer

![Go](https://img.shields.io/badge/Language-Go_1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Linux](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-T1110_Brute_Force-C8102E?style=for-the-badge&logo=target&logoColor=white)
![Blue Team](https://img.shields.io/badge/Focus-SOC_%26_Threat_Hunting-005571?style=for-the-badge)

## 📌 Overview

**Go-Log-Hunter** is a lightweight, zero-dependency command-line tool written in **Go (Golang)** designed for SOC Analysts and Incident Responders. It parses Linux authentication logs (`/var/log/auth.log` or `secure`) at high speed to detect **SSH Brute-Force** and password spraying attempts (**MITRE ATT&CK T1110**), aggregating offending source IP addresses based on a customizable alert threshold.

### Why Go (Golang) for SecOps?
- **High Performance:** Uses buffered streaming (`bufio.Scanner`) to process large log files with minimal memory footprint.
- **Zero Dependencies:** Compiles into a single standalone static binary that can be dropped directly onto any compromised or monitored Linux server during incident triage without requiring Python environments or external libraries.

---

## ⚙️ Features
- Parses standard OpenSSH `Failed password` events (valid and invalid users).
- Aggregates and ranks attacking IPv4 addresses by failure count.
- Configurable alert threshold flag (`-threshold`) to filter out noise and highlight true brute-force anomalies.
- Outputs structured telemetry ready for firewall blocklists (`ufw` / `iptables`) or SIEM/SOAR ingestion.

---

## 🚀 Usage

### 1. Clone and Build
```bash
git clone [https://github.com/rcybershield/go-log-hunter.git](https://github.com/rcybershield/go-log-hunter.git)
cd go-log-hunter
go build -o go-log-hunter main.go
```

### 2. Run Against Linux Auth Logs
```bash
./go-log-hunter -log /var/log/auth.log -threshold 5
```

### 📊 Example Output
```text
=============================================================
 🛡️  GO-LOG-HUNTER | SSH Brute-Force Detection (T1110)
=============================================================
[*] Scanning log file: /var/log/auth.log
[*] Alert Threshold:   5 failed attempts

[!] SUSPICIOUS IPs DETECTED:
-------------------------------------------------------------
IP ADDRESS          FAILED ATTEMPTS     STATUS
-------------------------------------------------------------
192.168.1.105       48                  [CRITICAL - BLOCK]
45.133.1.22         14                  [HIGH - INVESTIGATE]
10.0.0.54           6                   [WARNING]
-------------------------------------------------------------
[+] Analysis complete. Total failed events parsed: 71
```

---
*Developed by **Rafael Laporte** – [LinkedIn](https://www.linkedin.com/in/rafaellaporte)*
