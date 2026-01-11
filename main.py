from plyer import notification
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import email_detector
import url_detector
import pystray
from pystray import MenuItem as item
import PIL.Image
import threading
import os
import requests 
import json
import imaplib
import email
from datetime import datetime
import client_email_config
import psutil
import clipboard_monitor
import browser_monitor
from urllib.parse import urlparse

GITHUB_REPO = "Pasindu-sd/Windows-PhishGuard"
RELEASES_URL = f"https://github.com/{GITHUB_REPO}/releases/latest"
UPDATE_ZIP_URL = f"https://github.com/{GITHUB_REPO}/releases/latest/update.zip"
RULES_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/phishing_rules.json"

CURRENT_VERSION = "1.0.0"

UPDATE_CHECK_INTERVAL = 24 * 60 * 60 * 1000
EMAIL_MONITOR_CHECK_INTERVAL = 30
HISTORY_MAX_ENTRIES = 100
PROCESS_SCAN_TIMEOUT = 5

DANGEROUS_PROCESSES = ["mimikatz", "netcat", "nc.exe"]
SUSPICIOUS_PROCESSES = ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe"]
SYSTEM32_SAFE_PATH = "system32"


class SecurityApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Windows PhishGuard")
        self.window.geometry("700x600")
        self.window.configure(bg="#4627f5")
        self.window.minsize(500, 400)
        
        self.history_file = "scan_history.json"
        self.scan_history = []
        self.load_history()
        
        self.email_monitor_thread = None
        self.email_monitor_stop_event = threading.Event()
        self.email_monitor_running = False
        
        self.clipboard_monitor = None
        self.browser_monitor = None
        self.real_time_protection_active = False
        self.rt_status_label = None
        
        self.tray_icon = None
        self.is_minimized_to_tray = False
        self.last_update_check = None
        self.update_available = False
        
        self.email_text = None
        self.email_result = None
        self.url_entry = None
        self.url_result = None
        self.status_label = None
        self.update_status_label = None
        self.history_text = None
        self.history_stats = None
        
        self.create_tabs()
        self.create_system_tray()
        self.setup_real_time_monitors()
        
        self.window.protocol('WM_DELETE_WINDOW', self.minimize_to_tray)
        self.window.after(2000, self.show_protection_message)
        self.window.after(5000, self.check_for_updates)
    
    def check_for_updates(self):
        """Check for updates from GitHub releases."""
        try:
            response = requests.get(RELEASES_URL, timeout=10)
            
            if response.status_code == 200:
                latest_version = response.json().get('tag_name', CURRENT_VERSION)
                
                if latest_version != CURRENT_VERSION:
                    self.update_available = True
                    self.show_update_notification(latest_version)
                else:
                    print("Tool is up-to-date")
            
            self.last_update_check = datetime.now()
        
        except (requests.RequestException, OSError) as e:
            print("Unable to check for updates due to lack of internet connection.")
        
        self.window.after(UPDATE_CHECK_INTERVAL, self.check_for_updates)
    
    def setup_real_time_monitors(self):
        """Setup real-time clipboard and browser monitors."""
        try:
            self.clipboard_monitor = clipboard_monitor.ClipboardMonitor(
                callback_function=self.handle_clipboard_url
            )
            
            self.browser_monitor = browser_monitor.BrowserMonitor(
                callback_function=self.handle_browser_activity
            )
            
            print("Real-time monitors initialized successfully!")
            
        except Exception as e:
            print(f"Failed to initialize real-time monitors: {e}")
    
    def handle_clipboard_url(self, url):
        """Handle URL detected in clipboard."""
        try:
            print(f"Clipboard URL detected: {url}")
            
            result = url_detector.detect_url(url)
            
            if result == "PHISHING" or result == "DANGEROUS":
                self.show_notification(
                    "Dangerous URL in Clipboard!",
                    f"Phishing URL detected\n{url[:50]}..."
                )
                
                response = messagebox.askyesno(
                    "Dangerous URL Detected!",
                    f"A dangerous URL was found in your clipboard:\n\n"
                    f"{url[:100]}...\n\n"
                    f"Do you want to clear the clipboard?"
                )
                
                if response:
                    self.clipboard_monitor.clear_clipboard()
                
                self.add_to_history("Clipboard URL", url, "Dangerous")
            
            elif result == "SUSPICIOUS":
                self.show_notification(
                    "Suspicious URL in Clipboard",
                    f"Suspicious URL copied\n{url[:40]}..."
                )
                self.add_to_history("Clipboard URL", url, "Suspicious")
            
        except Exception as e:
            print(f"Error handling clipboard URL: {e}")
    
    def handle_browser_activity(self, data):
        """Handle suspicious browser activity."""
        try:
            url = data.get('url', '')
            browser = data.get('browser', 'Unknown')
            reason = data.get('reason', 'Suspicious activity detected')
            
            print(f"Browser Alert: {browser} - {reason}")
            
            self.show_notification(
                "Suspicious Browser Activity",
                f"Suspicious URL in {browser}\n{url[:60]}..."
            )
            
            self.add_to_history(f"Browser ({browser})", url, "Suspicious")
            
            response = messagebox.askyesno(
                "Suspicious Browser Activity Detected!",
                f"Browser: {browser}\n"
                f"URL: {url[:80]}...\n\n"
                f"Reason: {reason}\n\n"
                f"Do you want to block this website?"
            )
            
            if response:
                self.block_website(url)
                
        except Exception as e:
            print(f"Error handling browser activity: {e}")
    
    def block_website(self, url):
        """Block website by adding to hosts file."""
        try:
            hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            if domain:
                with open(hosts_path, 'a') as f:
                    f.write(f"\n127.0.0.1 {domain}")
                    f.write(f"\n127.0.0.1 www.{domain}")
                
                self.show_notification(
                    "Website Blocked",
                    f"{domain} has been blocked!"
                )
                print(f"Blocked website: {domain}")
            
        except PermissionError:
            messagebox.showerror(
                "Permission Denied",
                "Run PhishGuard as Administrator to block websites."
            )
        except Exception as e:
            print(f"Failed to block website: {e}")
    
    def start_real_time_protection(self):
        """Start all real-time protection features."""
        try:
            if self.clipboard_monitor:
                self.clipboard_monitor.start_monitoring()
            
            if self.browser_monitor:
                self.browser_monitor.start_monitoring(interval=15)
            
            self.real_time_protection_active = True
            
            if self.rt_status_label:
                self.rt_status_label.config(
                    text="Real-time Protection: ACTIVE",
                    fg="green"
                )
            
            self.show_notification(
                "Real-time Protection Started",
                "Clipboard and browser monitoring is now active!"
            )
            
            print("Real-time protection started!")
            
        except Exception as e:
            print(f"Failed to start real-time protection: {e}")
            messagebox.showerror("Error", f"Failed to start protection: {e}")
    
    def stop_real_time_protection(self):
        """Stop all real-time protection features."""
        try:
            if self.clipboard_monitor:
                self.clipboard_monitor.stop_monitoring()
            
            if self.browser_monitor:
                self.browser_monitor.stop_monitoring()
            
            self.real_time_protection_active = False
            
            if self.rt_status_label:
                self.rt_status_label.config(
                    text="Real-time Protection: INACTIVE",
                    fg="red"
                )
            
            self.show_notification(
                "Real-time Protection Stopped",
                "Monitoring has been stopped."
            )
            
            print("Real-time protection stopped!")
            
        except Exception as e:
            print(f"Error stopping real-time protection: {e}")
    
    def show_update_notification(self, new_version):
        if not self.is_minimized_to_tray:
            response = messagebox.askyesno("New Update Available", f"New Version {new_version} available!\nDo you want to update now?")
            if response:
                self.download_update()
                
        else:
            if self.tray_icon:
                self.tray_icon.notify(f"New version {new_version} available!", "Click to update")
    
    
    def show_notification(self, title, message, duration=5):
        try:
            notification.notify(title=title, message=message, app_name="Windows PhishGuard", timeout=duration)
        except (OSError, RuntimeError) as e:
            print(f"Notification error: {e}")
            self.window.after(0, lambda: messagebox.showinfo(title, message))
    
    def download_update(self):
        """Download latest update from GitHub releases."""
        try:
            messagebox.showinfo("Update", "Downloading update ...")
            response = requests.get(UPDATE_ZIP_URL, stream=True, timeout=30)
            
            if response.status_code == 200:
                with open("update.zip", "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                messagebox.showinfo("Success", "Update downloaded successfully!\nPlease restart the application.")
            else:
                messagebox.showerror("Error", "Update download failed!")
        
        except (OSError, requests.RequestException):
            messagebox.showerror("Error", "Update download failed!")
    
    
    def update_phishing_rules(self):
        """Update phishing detection rules from local file or GitHub."""
        try:
            if os.path.exists('phishing_rules.json'):
                with open('phishing_rules.json', 'r', encoding='utf-8') as f:
                    new_rules = json.load(f)
                    
                    if 'email_keywords' in new_rules:
                        email_detector.suspicious_keywords = new_rules['email_keywords']
                     
                    if 'url_patterns' in new_rules:
                        url_detector.suspicious_patterns = new_rules['url_patterns']
                    
                    print("Local phishing rules loaded successfully")
                    return
            response = requests.get(RULES_URL, timeout=10)

            if response.status_code == 200:
                new_rules = response.json()
                
                if 'email_keywords' in new_rules:
                    email_detector.suspicious_keywords = new_rules['email_keywords']
                 
                if 'url_patterns' in new_rules:
                    url_detector.suspicious_patterns = new_rules['url_patterns']
                
                print("Phishing rules successfully updated from GitHub")
                
        except (json.JSONDecodeError, requests.RequestException, OSError) as e:
            print(f"Rules update failed: {e}")
    
    def show_protection_message(self):
        messagebox.showinfo("Protection Active", "Your computer is now protected!")
    
    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.scan_history = json.load(f)
            else:
                self.scan_history = []
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"History load error: {e}")
            self.scan_history = []
    
    
    def save_history(self):
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_history[-100:], f, indent=2)
        except (OSError, IOError) as e:
            print(f"History save error: {e}")

    
    def add_to_history(self, scan_type, content, result):
        """Add scan result to history."""
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": scan_type,
            "content": content[:100] + "..." if len(content) > 100 else content,
            "result": result
        }
        
        self.scan_history.append(record)
        self.save_history()
        if len(self.scan_history) > HISTORY_MAX_ENTRIES:
            self.scan_history = self.scan_history[-HISTORY_MAX_ENTRIES:]
    
    def create_system_tray(self):
        try:    
            image = PIL.Image.new('RGB', (64, 64), color='green')
            
            menu = pystray.Menu(
                item('open up', self.restore_from_tray),
                item('Look', self.show_status),
                item('get out', self.quit_application)
            )
            
            self.tray_icon = pystray.Icon("phish_guard", image, "Windows PhishGuard", menu)
            
        except (OSError, AttributeError) as e:
            print(f"System tray creation error: {e}")
    
    def minimize_to_tray(self):
        if self.tray_icon:
            self.window.withdraw()
            self.is_minimized_to_tray = True
            tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
            tray_thread.start()
        else:
            self.window.destroy()
    
    def restore_from_tray(self, _icon=None, _tray_item=None):
        if self.is_minimized_to_tray:
            self.window.after(0, self.show_window)
    
    def show_window(self):
        self.window.deiconify()
        self.window.attributes('-topmost', True)
        self.window.attributes('-topmost', False)
        self.is_minimized_to_tray = False
        if self.tray_icon and self.tray_icon.visible:
            self.tray_icon.stop()
    
    def show_status(self, _icon=None, _tray_item=None):
        messagebox.showinfo("Status", "Windows PhishGuard is active!\nStay safe!")
    
    def quit_application(self, _icon=None, _tray_item=None):
        if self.tray_icon:
            self.tray_icon.stop()
        self.window.destroy()
        os._exit(0)
    
    def create_tabs(self):
        style = ttk.Style()
        style.configure('TNotebook.Tab', font=('Arial', 10, 'bold'))
        
        notebook = ttk.Notebook(self.window)
        
        tab1 = ttk.Frame(notebook, padding="10")
        tab1.pack(fill='both', expand=True)
        self.create_email_tab(tab1)
        
        tab2 = ttk.Frame(notebook, padding="10")
        tab2.pack(fill='both', expand=True)
        self.create_url_tab(tab2)
        
        tab3 = ttk.Frame(notebook, padding="10")
        tab3.pack(fill='both', expand=True)
        self.create_status_tab(tab3)
        
        tab4 = ttk.Frame(notebook, padding="10")
        tab4.pack(fill='both', expand=True)
        self.create_history_tab(tab4)
        
        tab5 = ttk.Frame(notebook, padding="10")
        tab5.pack(fill='both', expand=True)
        self.create_settings_tab(tab5)
        
        
        notebook.add(tab1, text="Email check")
        notebook.add(tab2, text="URL checking")
        notebook.add(tab3, text="Status")
        notebook.add(tab4, text="Scan History")
        notebook.add(tab5, text="Settings")
        notebook.pack(expand=True, fill='both')
    
    def create_email_tab(self, parent):
        title_label = tk.Label(parent, text="Check the email content", font=("Arial", 14, "bold"), fg="blue", bg='#f0f0f0')
        title_label.pack(pady=15)
        
        instr_label = tk.Label(parent, text="Copy the contents of the suspicious email and paste it into the box below:",font=("Arial", 10), bg='#f0f0f0', wraplength=500)
        instr_label.pack(pady=10)
        
        self.email_text = scrolledtext.ScrolledText(parent, height=15, width=80, font=("Arial", 10), bg='white')
        self.email_text.pack(pady=10, padx=20, fill='both', expand=True)
        
        button_frame = tk.Frame(parent, bg='#f0f0f0')
        button_frame.pack(pady=10)
        
        check_btn = tk.Button(button_frame, text="check", command=self.check_email,bg="green", fg="white", font=("Arial", 12, "bold"),padx=20, pady=5)
        check_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", command=self.clear_email,bg="orange", fg="white", font=("Arial", 12),padx=20, pady=5)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.email_result = tk.Label(parent, text="", font=("Arial", 12, "bold"), bg='#f0f0f0', wraplength=500)
        self.email_result.pack(pady=10)
    
    def create_url_tab(self, parent):
        title_label = tk.Label(parent, text="Check the URL", font=("Arial", 14, "bold"), fg="blue", bg='#f0f0f0')
        title_label.pack(pady=15)
        
        instr_label = tk.Label(parent, text="Enter the URL to check:",font=("Arial", 10), bg='#f0f0f0')
        instr_label.pack(pady=10, fill='x', padx=20)
        
        entry_frame = tk.Frame(parent, bg='#f0f0f0')
        entry_frame.pack(pady=10, fill='x', padx=20)
        
        tk.Label(entry_frame, text="URL:", font=("Arial", 10), bg='#f0f0f0').pack(side=tk.LEFT)
        self.url_entry = tk.Entry(entry_frame, width=60, font=("Arial", 12), bg='white')
        self.url_entry.pack(side=tk.LEFT, padx=10, fill='x', expand=True)
        
        button_frame = tk.Frame(parent, bg='#f0f0f0')
        button_frame.pack(pady=10, fill='x')
        
        check_btn = tk.Button(button_frame, text="Check the URL", command=self.check_url,bg="green", fg="white", font=("Arial", 12, "bold"),padx=20, pady=5)
        check_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", command=self.clear_url,bg="orange", fg="white", font=("Arial", 12),padx=20, pady=5)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.url_result = tk.Label(parent, text="", font=("Arial", 12, "bold"), bg='#f0f0f0', wraplength=500)
        self.url_result.pack(pady=10)
    
    def create_status_tab(self, parent):
        title_label = tk.Label(parent, text="System Status", 
                              font=("Arial", 14, "bold"), fg="green", bg='#f0f0f0')
        title_label.pack(pady=15)
        
        update_status = "Available" if self.update_available else "Up to date"
        update_color = "orange" if self.update_available else "green"
        
        status_text = f"""
                        Windows PhishGuard Active

                        Features Available:
                        • Email phishing detection
                        • URL phishing detection  
                        • Real-time protection
                        • System tray integration

                        Security Status: ACTIVE
                        Update Status: {update_status}
                        Last Update Check: {self.last_update_check or "Never"}
                        Threats Blocked: 0
                     """
        
        status_label = tk.Label(parent, text=status_text, font=("Arial", 10), bg='#f0f0f0', justify=tk.LEFT)
        status_label.pack(pady=5, fill='both', expand=True, padx=20)
        
        status_frame = tk.Frame(parent, bg='#f0f0f0')
        status_frame.pack(pady=5)
        
        self.status_label = tk.Label(status_frame, text="PROTECTION: ACTIVE", font=("Arial", 14, "bold"), fg="green", bg='#f0f0f0')
        self.status_label.pack()
        
        self.update_status_label = tk.Label(status_frame, text=f"UPDATES: {update_status}", 
                                          font=("Arial", 12, "bold"), fg=update_color, bg='#f0f0f0')
        self.update_status_label.pack(pady=5)
        
        tray_frame = tk.Frame(parent, bg='#f0f0f0')
        tray_frame.pack(pady=20)
    
    def create_settings_tab(self, parent):
        title_label = tk.Label(parent, text="Settings", font=("Arial", 14, "bold"), fg="blue", bg='#f0f0f0')
        title_label.pack(pady=15)
        
        instr_label = tk.Label(parent, text="Configure your application settings below:",font=("Arial", 10), bg='#f0f0f0')
        instr_label.pack(pady=10)
        
        tray_frame = tk.Frame(parent, bg='#f0f0f0')
        tray_frame.pack(pady=10)
        
        update_rules_btn = tk.Button(parent, text="Update Phishing Rules", command=self.update_phishing_rules,bg="purple", fg="white", font=("Arial", 12),padx=20, pady=5)
        update_rules_btn.pack(pady=20)
        
        update_btn = tk.Button(tray_frame, text="Check Updates", command=self.manual_update_check,bg="purple", fg="white", font=("Arial", 10), padx=10, pady=5)
        update_btn.pack(side=tk.LEFT, padx=5)
        
        minimize_btn = tk.Button(tray_frame, text="Minimize to tray", command=self.minimize_to_tray, bg="blue", fg="white", font=("Arial", 10), padx=10, pady=5)
        minimize_btn.pack(side=tk.LEFT, padx=5)
        
        quit_btn = tk.Button(tray_frame, text="get out", command=self.quit_application, bg="red", fg="white", font=("Arial", 10), padx=10, pady=5)
        quit_btn.pack(side=tk.LEFT, padx=5)
        
        quick_scan_btn = tk.Button(parent, text="Quick Scan", command=self.quick_scan, bg="blue", fg="white", font=("Arial", 12),padx=10, pady=10)
        quick_scan_btn.pack(padx=20)
        
        start_email_btn = tk.Button(parent, text="Start Auto Email Check", command=self.start_email_monitor, bg="green", fg="white", font=("Arial", 12), padx=15, pady=5)
        start_email_btn.pack(pady=5)

        stop_email_btn = tk.Button(parent, text="Stop Auto Email Check", command=self.stop_email_monitor, bg="red", fg="white", font=("Arial", 12), padx=15, pady=5)
        stop_email_btn.pack(pady=5)

        real_time_frame = tk.Frame(parent, bg='#f0f0f0')
        real_time_frame.pack(pady=15)
        
        rt_title_label = tk.Label(real_time_frame, text="Real-time Protection", font=("Arial", 12, "bold"), fg="darkblue", bg='#f0f0f0')
        rt_title_label.pack(pady=5)
        
        rt_btn_frame = tk.Frame(real_time_frame, bg='#f0f0f0')
        rt_btn_frame.pack(pady=10)
        
        start_rt_btn = tk.Button(rt_btn_frame,text="Start Real-time Protection",command=self.start_real_time_protection,bg="green", fg="white",font=("Arial", 11, "bold"),padx=20, pady=8)
        start_rt_btn.pack(side=tk.LEFT, padx=5)
        
        stop_rt_btn = tk.Button(rt_btn_frame,text="Stop Real-time Protection",command=self.stop_real_time_protection,bg="red", fg="white",font=("Arial", 11, "bold"),padx=20, pady=8)
        stop_rt_btn.pack(side=tk.LEFT, padx=5)
        
        self.rt_status_label = tk.Label(real_time_frame,text="Real-time Protection: INACTIVE",font=("Arial", 10),fg="red",bg='#f0f0f0')
        self.rt_status_label.pack(pady=5)
    
    def create_history_tab(self, parent):
        title_label = tk.Label(parent, text="Scan History", font=("Arial", 14, "bold"), fg="purple", bg='#f0f0f0')
        title_label.pack(pady=10)
        
        history_frame = tk.Frame(parent, bg='white', relief=tk.SUNKEN, bd=1)
        history_frame.pack(pady=10, padx=10, fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(history_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.history_text = tk.Text(history_frame, height=15, width=80, font=("Arial", 10), bg='white',yscrollcommand=scrollbar.set)
        self.history_text.pack(side=tk.LEFT, fill='both', expand=True)
        scrollbar.config(command=self.history_text.yview)
        
        button_frame = tk.Frame(parent, bg='#f0f0f0')
        button_frame.pack(pady=10)
        
        refresh_btn = tk.Button(button_frame, text="Refresh History", command=self.refresh_history,bg="blue", fg="white", font=("Arial", 10),padx=10, pady=5)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear History", command=self.clear_history,bg="red", fg="white", font=("Arial", 10),padx=10, pady=5)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        export_btn = tk.Button(button_frame, text="Export to File", command=self.export_history,bg="green", fg="white", font=("Arial", 10),padx=10, pady=5)
        export_btn.pack(side=tk.LEFT, padx=5)
        
        self.history_stats = tk.Label(parent, text="", font=("Arial", 10), bg='#f0f0f0', fg="blue")
        self.history_stats.pack(pady=5)
        
        self.refresh_history()
    
    def refresh_history(self):
        self.history_text.delete(1.0, tk.END)
        
        if not self.scan_history:
            self.history_text.insert(tk.END, "No scan history found.\n")
            self.history_stats.config(text="Total scans: 0")
            return
        
        for i, record in enumerate(reversed(self.scan_history), 1):
            timestamp = record.get('timestamp', 'Unknown')
            scan_type = record.get('type', 'Unknown')
            result = record.get('result', 'Unknown')
            content = record.get('content', '')
            
            if result == "Secure":
                color_tag = "green"
            elif result == "Suspicious":
                color_tag = "orange"
            else:
                color_tag = "red"
            
            entry = f"{i}. {timestamp} - {scan_type}\n"
            entry += f"   Result: {result}\n"
            entry += f"   Content: {content}\n"
            entry += "-" * 50 + "\n"
            
            self.history_text.insert(tk.END, entry)
            
            start_index = f"{i}.0"
            end_index = f"{i+1}.0"
            self.history_text.tag_config("green", foreground="green")
            self.history_text.tag_config("orange", foreground="orange")
            self.history_text.tag_config("red", foreground="red")   
            self.history_text.tag_add(color_tag, start_index, end_index)
        
        self.history_text.tag_config("green", foreground="green")
        self.history_text.tag_config("orange", foreground="orange")
        self.history_text.tag_config("red", foreground="red")
        
        total = len(self.scan_history)
        secure = sum(1 for r in self.scan_history if r.get('result') == 'Secure')
        suspicious = sum(1 for r in self.scan_history if r.get('result') == 'Suspicious')
        dangerous = sum(1 for r in self.scan_history if r.get('result') == 'Dangerous')
        
        stats_text = f"Total scans: {total} | Secure: {secure} | Suspicious: {suspicious} | Dangerous: {dangerous}"
        self.history_stats.config(text=stats_text)


    def clear_history(self):
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all scan history?"):
            self.scan_history = []
            self.save_history()
            self.refresh_history()
            self.show_notification("History Cleared", 
                                  "All scan history has been deleted")
            messagebox.showinfo("Success", "Scan history cleared!")


    def export_history(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"phishguard_history_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("PhishGuard Scan History Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                
                for record in self.scan_history:
                    f.write(f"Time: {record['timestamp']}\n")
                    f.write(f"Type: {record['type']}\n")
                    f.write(f"Result: {record['result']}\n")
                    f.write(f"Content: {record['content']}\n")
                    f.write("-" * 40 + "\n")
                
                f.write(f"\nTotal scans: {len(self.scan_history)}\n")
            self.show_notification("History Exported", f"Saved to {filename}")
            messagebox.showinfo("Export Successful", f"History exported to:\n{filename}")
        except (OSError, IOError) as e:
            self.show_notification("Export Failed", "Could not export history")
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    
    
    def quick_scan(self):
        self.show_notification("Quick Scan Started", "Scanning for threats...")
        
        results = self.scan_running_processes()
        if results:
            msg = ""
            for pid, name, path, severity in results:
                msg += f"PID: {pid}\nName: {name}\nLevel: {severity}\n\n"

            messagebox.showwarning("Threats Found", msg)
        else:
            messagebox.showinfo("Quick Scan", "No threats found. System looks clean.")
    
    
    def scan_running_processes(self):
        """Scan running processes for malicious threats."""
        found = []
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                name = proc.info['name'].lower()
                path = (proc.info['exe'] or "").lower()
                severity = None
                if any(d in name for d in DANGEROUS_PROCESSES):
                    severity = "Dangerous"
                elif any(s in name for s in SUSPICIOUS_PROCESSES):
                    if SYSTEM32_SAFE_PATH not in path:
                        severity = "Suspicious"
                if severity:
                    found.append((proc.pid, proc.info['name'], path, severity))

            except:
                continue

        return found
    
    def clear_email(self):
        self.email_text.delete("1.0", tk.END)
        self.email_result.config(text="")
    
    def clear_url(self):
        self.url_entry.delete(0, tk.END)
        self.url_result.config(text="")
    
    def check_email(self):
        email_content = self.email_text.get("1.0", tk.END).strip()

        if not email_content:
            messagebox.showwarning("Warning", "Please enter email content")
            return

        result = email_detector.check_phishing(email_content)

        if "safe email" in result:
            display_result = "A secure email"
            color = "green"
            result_type = "Secure"
            self.show_notification("Email Scan Complete", "This email is safe!")
        elif "suspicious" in result:
            display_result = "A suspicious email"
            color = "orange"
            result_type = "Suspicious"
            self.show_notification("Suspicious Email Found!", "This email might be phishing!")
        else:
            display_result = "A dangerous email!"
            color = "red"
            result_type = "Dangerous"
            self.show_notification("DANGEROUS EMAIL DETECTED!", "Phishing email detected! Be careful!")

        self.add_to_history("Email", email_content[:50], result_type)
        self.email_result.config(text=display_result, fg=color)
    
    def start_email_monitor(self):
        if self.email_monitor_thread and self.email_monitor_thread.is_alive():
            messagebox.showinfo("Warning", "Email monitoring Active!")
            return

        self.email_monitor_stop_event.clear()
        self.email_monitor_thread = threading.Thread(target=self.monitor_emails, daemon=True)
        self.email_monitor_thread.start()
        self.show_notification("Email Monitor", "Automatic email monitoring started!")
        messagebox.showinfo("Email Monitor", "Automatic email monitoring started!")

    def stop_email_monitor(self):
        if self.email_monitor_thread and self.email_monitor_thread.is_alive():
            self.email_monitor_stop_event.set()
            self.show_notification("Email Monitor", "Stopping email monitoring...")
            messagebox.showinfo("Email Monitor", "Stopping email monitoring...")
        else:
            messagebox.showinfo("Email Monitor", "Email monitoring is not running.")

    
    def check_url(self):
        url = self.url_entry.get().strip()
        
        if not url:
            messagebox.showwarning("Warning", "Please enter the URL")
            return
        
        if not url.startswith(("http://", "https://")):
            messagebox.showerror("Invalid URL", "Please enter a valid URL")
            return
        
        result = url_detector.detect_url(url)

        display_result = "A suspicious URL"
        color = "orange"
        result_type = "Suspicious"

        if result == "SAFE":
            display_result = "A secure URL"
            color = "green"
            result_type = "Secure"
            self.show_notification("URL Scan Complete", f"{url[:30]}... is safe!")
        elif result in ("PHISHING", "DANGEROUS"):
            display_result = "Dangerous URL!"
            color = "red"
            result_type = "Dangerous"
            self.show_notification("DANGEROUS URL DETECTED!", f"{url[:30]}... is dangerous!")
        elif result in ("SUSPICIOUS", "UNKNOWN", "WARN"):
            self.show_notification("Suspicious URL", f"{url[:30]}... looks suspicious!")

        self.add_to_history("URL", url, result_type)
        self.url_result.config(text=display_result, fg=color)

    
    
    def manual_update_check(self):
        messagebox.showinfo("Update Check", "Checking for updates...")
        self.check_for_updates()
        
        if self.update_available:
            self.update_status_label.config(text="UPDATES: Available", fg="orange")
        else:
            self.update_status_label.config(text="UPDATES: Up to date", fg="green")
            messagebox.showinfo("Update", "Your tool is up to date!")
    
    def run(self):
        print("Windows PhishGuard started!")
        print("App minimized to system tray. Click the tray icon to restore.")
        
        self.window.mainloop()

    
    
    def monitor_emails(self):
        config = client_email_config.get_config()
        EMAIL = config['email']
        PASSWORD = config['password']
        IMAP_SERVER = config['imap_server']

        imap = None
        try:
            imap = imaplib.IMAP4_SSL(IMAP_SERVER)
            imap.login(EMAIL, PASSWORD)
            imap.select("inbox")

            while not self.email_monitor_stop_event.is_set():
                _, messages = imap.search(None, 'UNSEEN')

                if messages[0]:
                    for num in messages[0].split():
                        if self.email_monitor_stop_event.is_set():
                            break

                        _, msg_data = imap.fetch(num, "(RFC822)")
                        msg = email.message_from_bytes(msg_data[0][1])

                        subject = msg.get("subject") or "No Subject"

                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    try:
                                        body = part.get_payload(decode=True).decode(errors='ignore')
                                    except (AttributeError, UnicodeDecodeError, TypeError):
                                        body = ""
                                    break
                        else:
                            try:
                                body = msg.get_payload(decode=True).decode(errors='ignore')
                            except (AttributeError, UnicodeDecodeError, TypeError):
                                body = ""

                        result = email_detector.check_phishing(f"{subject}\n{body}")

                        if "suspicious" in result or "dangerous" in result:
                            notification.notify(
                                title="PhishGuard Alert!",
                                message=f"Suspicious email detected: {subject[:50]}",
                                app_name="Windows PhishGuard",
                                timeout=5
                            )
                            if "suspicious" in result:
                                self.add_to_history("Email", body[:100], "Suspicious")
                            elif "dangerous" in result:
                                self.add_to_history("Email", body[:100], "Dangerous")

                        imap.store(num, '+FLAGS', '\\Seen')

                if self.email_monitor_stop_event.wait(EMAIL_MONITOR_CHECK_INTERVAL):
                    break

        except (imaplib.IMAP4.error, ConnectionError) as e:
            print(f"Email monitoring error: {e}")

        finally:
            try:
                if imap is not None:
                    imap.logout()
            except (ConnectionError, OSError):
                pass
            
            self.email_monitor_thread = None
            print("Email monitoring stopped")
    

if __name__ == "__main__":
    app = SecurityApp()
    app.run()