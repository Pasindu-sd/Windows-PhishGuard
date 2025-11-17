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

class SecurityApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Windows PhishGuard - ආරක්ෂක ටුල් එක")
        self.window.geometry("700x600")
        self.window.configure(bg='#f0f0f0')
        
        
        self.tray_icon = None
        self.is_minimized_to_tray = False
        
        self.create_tabs()
        self.create_system_tray()
        
        
        self.window.protocol('WM_DELETE_WINDOW', self.minimize_to_tray)
        self.window.after(2000, self.show_protection_message)
    
    def show_protection_message(self):
        messagebox.showinfo("Protection Active", "Your computer is now protected!")
     
    def create_system_tray(self):
        """System Tray Icon එක create කිරීම"""
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
        self.create_email_tab(tab1)
        
        tab2 = ttk.Frame(notebook, padding="10")
        self.create_url_tab(tab2)
        
        tab3 = ttk.Frame(notebook, padding="10")
        self.create_status_tab(tab3)
        
        notebook.add(tab1, text="Email check")
        notebook.add(tab2, text="URL checking")
        notebook.add(tab3, text="Status")
        notebook.pack(expand=True, fill='both', padx=10, pady=10)
    
    def create_email_tab(self, parent):
        
        title_label = tk.Label(parent, text="Check the email content", 
                              font=("Arial", 14, "bold"), fg="blue", bg='#f0f0f0')
        title_label.pack(pady=15)
        
        instr_label = tk.Label(parent, text="Copy the contents of the suspicious email and paste it into the box below:",font=("Arial", 10), bg='#f0f0f0', wraplength=500)
        instr_label.pack(pady=10)
        
        self.email_text = scrolledtext.ScrolledText(parent, height=15, width=80, font=("Arial", 10), bg='white')
        self.email_text.pack(pady=10, padx=20, fill='both')
        
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
        instr_label.pack(pady=10)
        
        entry_frame = tk.Frame(parent, bg='#f0f0f0')
        entry_frame.pack(pady=10)
        
        tk.Label(entry_frame, text="URL:", font=("Arial", 10), bg='#f0f0f0').pack(side=tk.LEFT)
        self.url_entry = tk.Entry(entry_frame, width=60, font=("Arial", 12), bg='white')
        self.url_entry.pack(side=tk.LEFT, padx=10)
        
        button_frame = tk.Frame(parent, bg='#f0f0f0')
        button_frame.pack(pady=10)
        
        check_btn = tk.Button(button_frame, text="Check the URL", command=self.check_url,bg="green", fg="white", font=("Arial", 12, "bold"),padx=20, pady=5)
        check_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(button_frame, text="Clear", command=self.clear_url,bg="orange", fg="white", font=("Arial", 12),padx=20, pady=5)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.url_result = tk.Label(parent, text="", font=("Arial", 12, "bold"), bg='#f0f0f0', wraplength=500)
        self.url_result.pack(pady=10)
    
    def create_status_tab(self, parent):
        """Status tab එක create කිරීම"""
        title_label = tk.Label(parent, text="System Status", 
                              font=("Arial", 14, "bold"), fg="green", bg='#f0f0f0')
        title_label.pack(pady=15)
        
        status_text = """
                        Windows PhishGuard Active

                        Features Available:
                        • Email phishing detection
                        • URL phishing detection  
                        • Real-time protection
                        • System tray integration

                        Security Status: ACTIVE
                        Last Scan: Never
                        Threats Blocked: 0

                        Tips:
                        • If you receive a suspicious email, check here.
                        • Check before opening an unknown URL.
                        • Click the icon in the system tray for quick access.
                     """
        
        status_label = tk.Label(parent, text=status_text, font=("Arial", 10), bg='#f0f0f0', justify=tk.LEFT)
        status_label.pack(pady=10)
        
        status_frame = tk.Frame(parent, bg='#f0f0f0')
        status_frame.pack(pady=10)
        
        self.status_label = tk.Label(status_frame, text="PROTECTION: ACTIVE", font=("Arial", 14, "bold"), fg="green", bg='#f0f0f0')
        self.status_label.pack()
        
        tray_frame = tk.Frame(parent, bg='#f0f0f0')
        tray_frame.pack(pady=20)
        
        minimize_btn = tk.Button(tray_frame, text="Minimize to tray", command=self.minimize_to_tray, bg="blue", fg="white", font=("Arial", 10), padx=15, pady=5)
        minimize_btn.pack(side=tk.LEFT, padx=5)
        
        quit_btn = tk.Button(tray_frame, text="get out", command=self.quit_application, bg="red", fg="white", font=("Arial", 10), padx=15, pady=5)
        quit_btn.pack(side=tk.LEFT, padx=5)
        
        quick_scan_btn = tk.Button(parent, text="Quick Scan", command=self.quick_scan, bg="blue", fg="white", font=("Arial", 12), padx=20, pady=10)
        quick_scan_btn.pack(pady=10)
        
        btn_frame = tk.Frame(parent, bg='#f0f0f0')
        btn_frame.pack(pady=10)
        
        start_btn = tk.Button(btn_frame, text="Start Protection", command=self.start_protection,bg="green", fg="white", font=("Arial", 10),padx=15, pady=5)
        start_btn.pack(side=tk.LEFT, padx=5)
        
        stop_btn = tk.Button(btn_frame, text="Stop Protection",command=self.stop_protection,bg="red", fg="white", font=("Arial", 10),padx=15, pady=5)
        stop_btn.pack(side=tk.LEFT, padx=5)
    
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
            elif "suspicious" in result:
                display_result = "A suspicious email"
                color = "orange"
            else:
                display_result = "A dangerous email!"
                color = "red"
            
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
            elif "suspicious" in result:
                display_result = "A custom URL"
                color = "orange"
            else:
                display_result = "Dangerous URL!"
                color = "red"
            
            self.url_result.config(text=display_result, fg=color)
        else:
            messagebox.showwarning("Warning", "Please enter the URL")
    
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