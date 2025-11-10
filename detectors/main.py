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