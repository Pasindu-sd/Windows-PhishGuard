import tkinter as tk
from tkinter import messagebox, scrolledtext
import email_detector
import url_detector

class SecurityApp:
   def __init__(self):
      self.window = tk.Tk()
      self.window.title("My Secure Tool")
      self.window.geometry("600*500")
      
      self.create_tabs()
   
   def create_tabs(self):
      notebook = tk.ttk.Notebook(self.window)
      
      tab1 = tk.Frame(notebook)
      self.create_email_tab(tab1)
      
      tab2 = tk.Frame(notebook)
      self.create_url_tab(tab2)
      
      notebook.add(tab1, text="Check email")
      notebook.add(tab2, text="Check URL")
      notebook.pack(expad=True, fill='both')