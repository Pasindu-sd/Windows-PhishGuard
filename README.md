# Windows-PhishGuard

![Python Version](https://img.shields.io/badge/Python-3.11+-blue)
![License](https://img.shields.io/badge/License-Proprietary-red)
![Status](https://img.shields.io/badge/Status-Under%20Development-yellow)

⚠️ **License:** Windows-PhishGuard is proprietary. You may view the code, but copying, redistribution, or modification is strictly prohibited.

A **powerful Windows security application** designed to proactively detect and alert users about potential phishing websites, helping safeguard personal information and credentials from online threats.

### Project Structure:

```
  phishguard/
    AIDetector/
    ├── __pycache__/
    │   ├── features.cpython-313.pyc
    │   └── features.cpython-314.pyc
    ├── check.py
    ├── features.py
    ├── model.pkl
    ├── train.py
    ├── urls.csv
    ├── browser_monitor.py
    ├── client_email_config.py
    ├── clipboard_monitor.py
    ├── email_config.json
    ├── email_detector.py
    ├── image.png
    ├── LICENSE
    ├── local_api.py
    ├── main.py
    ├── phishing_rules.json
    ├── README.md
    ├── requirements.txt
    ├── scan_history.json
    └── url_detector.py
```

## Overview

**Windows PhishGuard** acts as the first line of defense against phishing attacks. It analyzes websites in real-time, checks URLs against known phishing databases, and uses heuristic analysis to identify suspicious patterns. Users are warned before entering sensitive data.  

Phishing is one of the most common cyber threats, and this tool adds an extra layer of protection for everyday Windows users.


---

## Features

- **Real-time URL Analysis**: Automatically scans URLs visited in the browser.  
- **Instant Alerts**: Displays non-intrusive pop-up warnings for suspected phishing sites.  
- **Heuristic Checks**: Analyzes page content, domain age, and SSL certificates to detect suspicious patterns.  
- **Community Blocklists**: Integrates with crowdsourced phishing and malware domain lists.  
- **Low System Impact**: Lightweight and efficient in the background.  
- **User-Friendly Interface**: Simple settings panel to configure sensitivity and view detection history.

---

## Getting Started

### Prerequisites

- **Operating System**: Windows 10 or Windows 11.
- **.NET Framework**: Ensure you have the latest .NET Desktop Runtime (or the version specified in the build) installed. [Download here if needed](https://dotnet.microsoft.com/download/dotnet).
- **Python 3.11+** (for running from source)

### Installation

1.  Go to the [Releases](https://github.com/Pasindu-sd/Windows-PhishGuard/releases) page of this repository.
2.  Download the latest `Windows-PhishGuard-Setup.exe` file.
3.  Run the installer and follow the on-screen instructions.
4.  Launch **Windows PhishGuard** from your Start Menu.

*(Note: As the project is under development, the release might not be available yet. Check back soon!)*

---

### Building from Source

If you want to build the application yourself:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Pasindu-sd/Windows-PhishGuard.git
    cd Windows-PhishGuard
    pip install -r requirements.txt
    python main.py
    ```

    Sample :

    ![alt text](image.png)

---


## Usage

Once installed and running, Windows PhishGuard will sit quietly in your system tray (notification area).

- It will automatically monitor your web traffic.
- If a potential phishing site is detected, a warning notification will appear.
- You can right-click the system tray icon to:
    - **Pause/Resume** protection.
    - **View** the detection log.
    - **Open** the settings window.
    - **Exit** the application.

---

## Disclaimer

- Only use onztest or personal environments.
- Do not use for unauthorized access or illegal activities.
- This tool is under development, features may change.
