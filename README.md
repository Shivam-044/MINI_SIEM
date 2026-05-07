# 🛡️ Windows Mini-SIEM (Security Information & Event Management)

A lightweight, modular, and functional SIEM system built from scratch using Python. This project demonstrates a full security data pipeline: from low-level Windows Event ingestion to real-time threat detection and visualization.

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)
![OS](https://img.shields.io/badge/OS-Windows-0078D4.svg)

---

## 📖 Overview
Most security students learn to use tools like Splunk or Wazuh. This project aims to understand the **mechanics** behind those tools by building a "Mini-SIEM" that monitors a local Windows environment for suspicious activity, specifically focusing on authentication security.

### Key Features
*   **Real-time Ingestion:** Hooks into the Windows Kernel via `pywin32` to stream Security Event Logs.
*   **Structured Storage:** Normalizes messy raw log text into a structured SQLite database.
*   **Correlation Engine:** A dedicated backend service that monitors login patterns and detects **Brute Force Attacks** using time-window analysis.
*   **Security Dashboard:** A professional web UI built with Streamlit to visualize login trends and high-priority alerts.

---

## 🏗️ Architecture
The system consists of three independent modules working in parallel:

1.  **The Collector (`collector.py`):** The "Ears" of the system. Monitors Event ID 4624 (Success) and 4625 (Failure).
2.  **The Brain (`engine.py`):** The "Logic." It queries the DB to find patterns (e.g., 5+ failures in 60s).
3.  **The UI (`app.py`):** The "Face." A Streamlit dashboard for real-time monitoring and reporting.

---

## 🚀 Getting Started

### Prerequisites
*   **Windows OS** (Required for Event Log access)
*   **Python 3.10+**
*   **Administrator Privileges** (Required to read Security Logs)

### Installation
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Shivam-044/MINI_SIEM.git](https://github.com/Shivam-044/MINI_SIEM.git)
   cd MINI_SIEM

```bash
# Continue from Installation...
pip install -r requirements.txt

# Terminal 1: Start the Log Collector
python collector.py

# Terminal 2: Start the Detection Engine
python engine.py

# Terminal 3: Launch the Dashboard
streamlit run app.py

---

## 🧪 Testing the Detection
To verify the SIEM is working:
1. Lock your Windows machine (`Win + L`).
2. Intentionally enter an incorrect password **5+ times**.
3. Log in correctly and check the **Streamlit Dashboard** or the **Engine Terminal**.
4. You should see a **RED** High-Priority Alert for a "Brute Force Attempt."

---

## 🛠️ Tech Stack
*   **Language:** Python
*   **Libraries:** `pywin32` (Windows API), `pandas` (Data handling), `sqlite3` (Storage), `streamlit` (UI).
*   **Security Focus:** Log Analysis, Correlation Rules, Incident Monitoring.

---

## 👤 Author
**Shivam**
*   B.Tech CSE Core (2nd Year)
*   Interest: Cybersecurity & Security Engineering
*   GitHub: [@Shivam-044](https://github.com/Shivam-044)

---

> **Disclaimer:** This tool is for educational purposes only. Always ensure you have permission before monitoring systems or conducting security tests.