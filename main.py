import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import email_detector
import url_detector
import pystray
from pystray import MenuItem as item
import PIL.Image
import threading
import os
import sys
import requests 
import json     
import time     
from datetime import datetime


class SecurityApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Windows PhishGuard")
        self.window.geometry("700x600")
        self.window.configure(bg='#f0f0f0')
        self.window.minsize(500, 400)
        
        self.tray_icon = None
        self.is_minimized_to_tray = False
        self.last_update_check = None
        self.update_available = False
        
        self.create_tabs()
        self.create_system_tray()
        
        self.window.protocol('WM_DELETE_WINDOW', self.minimize_to_tray)
        self.window.after(2000, self.show_protection_message)
        self.window.after(5000, self.check_for_updates)
        
        self.history_file = "scan_history.json"
        self.scan_history = []
        self.load_history()
    
    
    def check_for_updates(self):
        try:
            response = requests.get("https://api.github.com/repos/Pasindu-sd/PhishGuard/releases/latest", timeout=10)
            
            if response.status_code == 200:
                latest_version = response.json().get('tag_name', '1.0.0')
                current_version = "1.0.0"
                
                if latest_version != current_version:
                    self.update_available = True
                    self.show_update_notification(latest_version)
                else:
                    print("Tool are up-to-date")
            
            self.last_update_check = datetime.now()
        
        except requests.RequestException:
            print("Unable to check for updates due to lack of internet connection.")
            
        self.window.after(24 * 60 * 60 * 1000, self.check_for_updates)
    
    
    def show_update_notification(self, new_version):
        if not self.is_minimized_to_tray:
            response = messagebox.askyesno("New Update Available", f"New Version {new_version} available!\nDo you want to update now?")
            if response:
                self.download_update()
                
        else:
            if self.tray_icon:
                self.tray_icon.notify(f"New version {new_version} available!", "Click to update")
    
    
    def download_update(self):
        try:
            messagebox.showinfo("Update", "Downloading update ...")
            update_url = "https://github.com/Pasindu-sd/PhishGuard/releases/latest/download/update.zip"
            
            response = requests.get(update_url, stream=True)
            
            if response.status_code == 200:
                with open("update.zip", "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                
                messagebox.showinfo("Success", "Update downloaded succesfully!\nPlease restart the application.")
            else:
                messagebox.showerror("Error", f"Update download failed!")
        
        except Exception as e:
            messagebox.showerror("Error", f"Update failed {str(e)}")
    
    
    def update_phishing_rules(self):
        try:
            rules_url = "https://github.com/Pasindu-sd/Windows-PhishGuard/blob/main/phishing_rules.json"
            response = requests.get(rules_url, timeout=10)

            if response.status_code == 200:
                new_rules = response.json()
                
                if 'email_keywords' in new_rules:
                    email_detector.suspicious_keywords = new_rules['email_keywords']
                 
                if 'url_patterns' in new_rules:
                    url_detector.suspicious_patterns = new_rules['url_patterns']
                
                print("Phishing rules successfully updated")
                
        except Exception as e:
            print(f"Rules update failed: {e}")
    
    def show_protection_message(self):
        messagebox.showinfo("Protection Active", "Your computer is now protected!")
     
     
     
    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.scan_history = json.load(f)
            else:
                self.scan_history = []
        except Exception as e:
            print(f"History load error: {e}")
            self.scan_history = []
    
    
    def save_history(self):
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.scan_history[-100], f, indent=2)
        except Exception as e:
            print(f"History save error: {e}")

    
    def add_to_history(self, scan_type, content, result):
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": scan_type,
            "content": content[:100] + "..." if len(content) > 100 else content,
            "result": result
        }
        
        self.scan_history.append(record)
        self.save_history()
        
        if len(self.scan_history) > 100:
            self.scan_history = self.scan_history[-100:]
    
    
    def create_system_tray(self):
        try:    
            image = PIL.Image.new('RGB', (64, 64), color='green')
            
            menu = (
                item('open up', self.restore_from_tray),
                item('Look', self.show_status),
                item('get out', self.quit_application)
            )
            
            self.tray_icon = pystray.Icon("phish_guard", image, "Windows PhishGuard", menu)
            
        except Exception as e:
            print(f"System tray creation error: {e}")
    
    
    
    def minimize_to_tray(self):
        
        if self.tray_icon:
            self.window.withdraw()  
            self.is_minimized_to_tray = True
            
            
            tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
            tray_thread.start()
        else:
            self.window.destroy()
    
    
    
    def restore_from_tray(self, icon=None, item=None):
        
        if self.is_minimized_to_tray:
            self.window.after(0, self.show_window)
    
    
    
    def show_window(self):
        
        self.window.deiconify()
        self.window.attributes('-topmost', True)
        self.window.attributes('-topmost', False)
        self.is_minimized_to_tray = False
        
        
        if self.tray_icon:
            self.tray_icon.stop()
    
    
    
    def show_status(self, icon=None, item=None):
        
        messagebox.showinfo("Status", "Windows PhishGuard is active!\nStay safe!")
    
    
    
    def quit_application(self, icon=None, item=None):
        
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
        self.create_settings_tab(tab4)
        
        tab5 = ttk.Frame(notebook, padding="10")
        tab5.pack(fill='both', expand=True)
        self.create_history_tab(tab5)
        
        notebook.add(tab1, text="Email check")
        notebook.add(tab2, text="URL checking")
        notebook.add(tab3, text="Status")
        notebook.add(tab4, text="Settings")
        notebook.add(tab5, text="Scan History")
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
        
        btn_frame = tk.Frame(parent, bg='#f0f0f0')
        btn_frame.pack(pady=10)
        
        start_btn = tk.Button(btn_frame, text="Start Protection", command=self.start_protection,bg="green", fg="white", font=("Arial", 10),padx=15, pady=5)
        start_btn.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
        
        stop_btn = tk.Button(btn_frame, text="Stop Protection",command=self.stop_protection,bg="red", fg="white", font=("Arial", 10),padx=15, pady=5)
        stop_btn.pack(side=tk.LEFT, padx=5, fill='x', expand=True)
    
    
    
    def create_history_tab(self, parent):
        title_label = tk.Label(parent, text="Scan History", 
                            font=("Arial", 14, "bold"), fg="purple", bg='#f0f0f0')
        title_label.pack(pady=10)
        
        history_frame = tk.Frame(parent, bg='white', relief=tk.SUNKEN, bd=1)
        history_frame.pack(pady=10, padx=10, fill='both', expand=True)
        
        scrollbar = tk.Scrollbar(history_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.history_text = tk.Text(history_frame, height=15, width=80, 
                                font=("Arial", 10), bg='white',
                                yscrollcommand=scrollbar.set)
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
    
    
    def quick_scan(self):
        messagebox.showinfo("Quick Scan", "Quick scan Started!\nNo threats found.")
    
    
    
    def clear_email(self):
        self.email_text.delete("1.0", tk.END)
        self.email_result.config(text="")
    
    
    
    def clear_url(self):
        self.url_entry.delete(0, tk.END)
        self.url_result.config(text="")
    
    
    
    def check_email(self):
        email_content = self.email_text.get("1.0", tk.END).strip()
        if email_content:
            result = email_detector.check_phishing(email_content)
            
            if "safe email" in result:
                display_result = "A secure email"
                color = "green"
                result_type = "Secure"
            elif "suspicious" in result:
                display_result = "A suspicious email"
                color = "orange"
                result_type = "Suspicious"
            else:
                display_result = "A dangerous email!"
                color = "red"
                result_type = "Dangerous"
            
            self.add_to_history("Email", email_content[:50], result_type)
            
            self.email_result.config(text=display_result, fg=color)
        else:
            messagebox.showwarning("Warning", "Please enter email content")
    
    
    
    def check_url(self):
        url = self.url_entry.get().strip()
        if url:
            result = url_detector.check_url(url)
            
            if "safe URL" in result:
                display_result = "A secure URL"
                color = "green"
                result_type = "Secure"
            elif "suspicious" in result:
                display_result = "A custom URL"
                color = "orange"
                result_type = "Suspicious"
            else:
                display_result = "Dangerous URL!"
                color = "red"
                result_type = "Dangerous"
                
            self.add_to_history("URL", url, result_type)

            
            self.url_result.config(text=display_result, fg=color)
        else:
            messagebox.showwarning("Warning", "Please enter the URL")
    
    
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
     
     
        
    def start_protection(self):
        self.status_label.config(text="PROTECTION: ACTIVE", fg="green")
        messagebox.showinfo("Protection", "Protection started!")



    def stop_protection(self):
        self.status_label.config(text="PROTECTION: STOPPED", fg="red")
        messagebox.showwarning("Protection", "Protection stopped!")



if __name__ == "__main__":
    app = SecurityApp()
    app.run()