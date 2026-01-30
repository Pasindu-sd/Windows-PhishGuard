import json
import os

CONFIG_FILE = "email_config.json"

def get_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(
            "Email configuration not found. "
            "Please set email details from Email Setup tab."
        )

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "email": data.get("email"),
        "password": data.get("password"),
        "imap_server": data.get("imap_server", "imap.gmail.com")
    }
