# 🛡️ Windows Mini-SIEM: Enterprise SOC Edition

A high-performance, modular Security Information and Event Management (SIEM) system built with Python. This project simulates a professional Security Operations Center (SOC) environment, featuring automated log ingestion, a stateful correlation engine, and a modern "Glassmorphism" analytics dashboard.

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg?logo=streamlit&logoColor=white)
![Windows](https://img.shields.io/badge/Platform-Windows-0078D4.svg?logo=windows&logoColor=white)

---

## 📖 Project Overview
This isn't just a log viewer. The **Windows Mini-SIEM** is a multi-threaded security pipeline designed to monitor, analyze, and visualize authentication threats in real-time. By bridging the gap between low-level Windows APIs and high-level data visualization, this tool provides a "Single Pane of Glass" for local endpoint security.

### 🌟 Advanced Features
*   **Single-Command Orchestration:** Launch the entire ecosystem (Ingestor, Brain, and UI) via a master `main.py` launchpad.
*   **Elegant SOC Dashboard:** A professional, minimalist UI featuring **Glassmorphism** styling, desaturated "Enterprise" colors, and interactive Plotly analytics.
*   **Stateful Correlation:** Detects complex patterns like **Brute Force Attacks** (5+ failures within 60s) using real-time SQL querying.
*   **Incident Response Toolkit:** Built-in features to filter logs by user/IP and **Export Incident Data to CSV** for forensic reporting.
*   **System Health Monitoring:** Integrated mock-telemetry to simulate a full-scale security appliance monitor.

---

## 🏗️ System Architecture
The project follows a modular **Microservices-style architecture**:

1.  **Orchestrator (`main.py`):** Manages process lifecycles and ensures graceful shutdowns.
2.  **Collector (`collector.py`):** Utilizes `pywin32` to hook into the Windows Kernel Event Log (EID 4624/4625).
3.  **Brain (`engine.py`):** The detection layer. It performs time-window analysis on incoming logs.
4.  **Analytics UI (`app.py`):** The visualization layer using Streamlit and Plotly for deep-dive forensics.

---

## 🚀 Deployment & Usage

### 📋 Prerequisites
*   **OS:** Windows 10/11 (Required for Event Log Access)
*   **Python:** 3.10 or higher
*   **Privileges:** Must be run as **Administrator**

### ⚙️ Installation
1.  **Clone the Repository:**
    git clone [https://github.com/Shivam-044/MINI_SIEM.git](https://github.com/Shivam-044/MINI_SIEM.git)

    cd MINI_SIEM

3.  **pip install -r requirements.txt**
 ### ⚡ Running the System
Forget opening multiple terminals. Start the entire security stack with one command:
     
     python main.py

👤 Author

<b> Shivam Kumar </b>

<i>B.Tech Computer Science (2nd Year) </i>

<i>Specialization: Cybersecurity & Security Engineering </i>

GitHub: @Shivam-044

<b>Legal Disclaimer:</b>
<i>This project is intended for educational and ethical security research only. Unauthorized monitoring of systems you do not own is strictly prohibited.</i>


---
