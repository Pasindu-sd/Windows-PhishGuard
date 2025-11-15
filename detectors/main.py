import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import email_detector
import url_detector

class SecurityApp:
   def __init__(self):
      self.window = tk.Tk()
      self.window.title("My Secure Tool")
      self.window.geometry("600x500")
      
      self.create_tabs()
   
   def create_tabs(self):
      notebook = ttk.Notebook(self.window)
      
      tab1 = tk.Frame(notebook)
      self.create_email_tab(tab1)
      
      tab2 = tk.Frame(notebook)
      self.create_url_tab(tab2)
      
      notebook.add(tab1, text="Check email")
      notebook.add(tab2, text="Check URL")
      notebook.pack(expand=True, fill='both')
      
   def create_email_tab(self, parent):
      label = tk.Label(parent, text="Enter email description")
      label.pack(pady=10)
      
      self.email_text = scrolledtext.ScrolledText(parent, height=10)
      self.email_text.pack(pady=10, padx=20, fill='both')
      
      check_btn = tk.Button(parent, text="Do Check", command=self.check_email)
      check_btn.pack(pady=10)
      
   def create_url_tab(self, parent):
      label = tk.Label(parent, text="Enter URL description")
      label.pack(pady=10)
      
      self.url_entry = tk.Entry(parent, width=50)
      self.url_entry.pack(pady=10)
      
      check_btn = tk.Button(parent, text="Check URL", command=self.check_url)
      check_btn.pack(pady=10)
      
      self.result_label = tk.Label(parent, text="", fg="blue")
      self.result_label.pack(pady=10)
      
   def check_email(self):
      email_content = self.email_text.get("1.0", tk.END)
      if email_content.strip():
         result = email_detector.check_phishing(email_content)
         messagebox.showinfo("Result", result)
      else:
         messagebox.showwarning("Warning", "Please enter the email description")
         
   def check_url(self):
      url = self.url_entry.get()
      if url:
         result = url_detector.check_url(url)
         self.result_label.config(text=result)
      else:
         messagebox.showwarning("Warning", "Please enter the URL")
   
   def run(self):
      self.window.mainloop()
   
if __name__ == "__main__":
   app = SecurityApp()
   app.run()