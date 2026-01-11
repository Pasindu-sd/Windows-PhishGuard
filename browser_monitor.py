import psutil
import time
import threading
import re
import os
from datetime import datetime

class BrowserMonitor:
    def __init__(self, callback_function=None):
        self.callback = callback_function
        self.monitoring = False
        self.monitor_thread = None
        
        self.browser_processes = [
            'chrome', 'firefox', 'msedge', 'opera', 'brave', 
            'safari', 'iexplore', 'chromium'
        ]
        
        self.suspicious_patterns = [
            r'login\.', r'verify\.', r'secure\.', r'account\.',
            r'password.*reset', r'bank.*login', r'paypal.*verify',
            r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$', r'\.gq$'
        ]
        
        self.whitelist = [
            'google.com', 'youtube.com', 'facebook.com', 'github.com',
            'microsoft.com', 'apple.com', 'amazon.com', 'wikipedia.org'
        ]
    
    def is_browser_process(self, process_name):
        process_lower = process_name.lower()
        for browser in self.browser_processes:
            if browser in process_lower:
                return True
        return False
    
    def check_url_suspicious(self, url):
        url_lower = url.lower()
        
        for safe_site in self.whitelist:
            if safe_site in url_lower:
                return False, "Whitelisted"
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url_lower):
                return True, f"Matches pattern: {pattern}"
        
        if len(url) > 100:
            return True, "URL too long"
        
        if url_lower.count('.') > 4:
            return True, "Too many subdomains"
        
        return False, "Looks safe"
    
    def extract_browser_urls(self):
        urls_found = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', '')
                    
                    if self.is_browser_process(proc_name):
                        cmdline = proc_info.get('cmdline', [])
                        
                        for arg in cmdline:
                            if arg and ('http://' in arg or 'https://' in arg):
                                url = arg.strip()
                                if '--' not in url:
                                    urls_found.append({
                                        'browser': proc_name,
                                        'url': url,
                                        'pid': proc_info['pid']
                                    })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return urls_found
        
        except Exception as e:
            print(f"Error extracting browser URLs: {e}")
            return []
    
    def start_monitoring(self, interval=10):
        if self.monitoring:
            print("Browser monitoring already active!")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        print(f"Browser monitoring started! (Checking every {interval} seconds)")
    
    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("Browser monitoring stopped!")
    
    def _monitor_loop(self, interval):
        checked_urls = set()
        
        while self.monitoring:
            try:
                current_time = datetime.now().strftime("%H:%M:%S")
                print(f"\n[{current_time}] Scanning browsers...")
                
                browser_urls = self.extract_browser_urls()
                
                if browser_urls:
                    print(f"Found {len(browser_urls)} browser tab(s)")
                    
                    for browser_data in browser_urls:
                        url = browser_data['url']
                        browser = browser_data['browser']
                        
                        url_hash = hash(url)
                        if url_hash in checked_urls:
                            continue
                        
                        checked_urls.add(url_hash)
                        
                        is_suspicious, reason = self.check_url_suspicious(url)
                        
                        if is_suspicious:
                            print(f"SUSPICIOUS URL in {browser}:")
                            print(f"   URL: {url[:80]}...")
                            print(f"   Reason: {reason}")
                            
                            if self.callback:
                                self.callback({
                                    'url': url,
                                    'browser': browser,
                                    'reason': reason,
                                    'timestamp': current_time
                                })
                        else:
                            print(f"Safe URL in {browser}: {url[:60]}...")
                else:
                    print("No active browser tabs found")
                

                time.sleep(interval)
                
            except Exception as e:
                print(f"Browser monitoring error: {e}")
                time.sleep(5)
    
    def get_active_browsers(self):
        active_browsers = []
        
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower()
                if self.is_browser_process(proc_name):
                    active_browsers.append(proc_name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return list(set(active_browsers))
