import pyperclip
import threading
import time
import re
from urllib.parse import urlparse

class ClipboardMonitor:
    def __init__(self, callback_function=None):
        self.callback = callback_function
        self.last_content = ""
        self.monitoring = False
        self.monitor_thread = None
        
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
    
    def extract_url_from_text(self, text):
        urls = self.url_pattern.findall(text)
        return urls[0] if urls else None
    
    def is_valid_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def start_monitoring(self):
        if self.monitoring:
            print("Clipboard monitoring already active!")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("Clipboard monitoring started!")
    
    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("Clipboard monitoring stopped!")
    
    def _monitor_loop(self):
        while self.monitoring:
            try:
                current_content = pyperclip.paste()
                
                if current_content and current_content != self.last_content:
                    self.last_content = current_content
                    
                    url = self.extract_url_from_text(current_content)
                    
                    if url and self.is_valid_url(url):
                        print(f"Clipboard URL detected: {url[:50]}...")
                        
                        if self.callback:
                            self.callback(url)
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"Clipboard monitoring error: {e}")
                time.sleep(1)
    
    def clear_clipboard(self):
        try:
            pyperclip.copy("")
            print("Clipboard cleared!")
        except Exception as e:
            print(f"Failed to clear clipboard: {e}")