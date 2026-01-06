# Windows-PhishGuard

that help to detect email phishing and url phishing

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

![alt text](image.png)
