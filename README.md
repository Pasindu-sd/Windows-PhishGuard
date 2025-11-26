# Windows-PhishGuard
A powerful and intuitive Windows application designed to proactively detect and alert users about potential phishing websites, helping to safeguard your personal information and credentials from online threats.

### Structure:
```
  phishguard/
    ├─ detectors/
    │  ├─ __init__.py
    │  ├─ email_detector.py    
    │  └─ url_detector.py      
    ├─ services/
    │  ├─ clipboard_watcher.py
    │  └─ outlook_reader.py   # optional
    ├─ storage/
    │  └─ db.py               # SQLite helper
    ├─ gui.py
    ├─ main.py                # CLI & glue
    ├─ requirements.txt
    └─ README.md
```

---

## Overview

**Windows PhishGuard** is a desktop security tool that acts as your first line of defense against phishing attacks. By analyzing websites in real-time, it checks URLs against known phishing databases and uses heuristic analysis to identify suspicious patterns, warning you before you enter any sensitive data.

Phishing is one of the most common cyber threats, and this tool aims to provide an additional layer of security for everyday Windows users.

---

## Features

- Real-time URL Analysis**: Automatically scans URLs you visit in your browser.
- Instant Alerts**: Displays clear, non-intrusive pop-up warnings for suspected phishing sites.
- Heuristic Checks**: Goes beyond blocklists to analyze page content, domain age, and SSL certificate status for suspicious characteristics.
- Community Blocklists**: Integrates with and updates from reputable, crowdsourced phishing and malware domain lists.
- Low System Impact**: Designed to be lightweight and run efficiently in the background.
- User-Friendly Interface**: Simple settings panel to configure sensitivity and view detection history.

---

