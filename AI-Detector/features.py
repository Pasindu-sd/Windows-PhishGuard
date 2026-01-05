import re

def extract_features(url):
   features = [
      len(url),                        # URL length
      url.count('.'),                   # number of dots
      url.count('-'),                   # number of dashes
      url.count('@'),                   # @ symbol
      1 if url.startswith("https") else 0,        # HTTPS = safe
      1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,  # IP address
      1 if any(x in url.lower() for x in ['login','verify','bank','secure']) else 0,  # suspicious words
      url.count('?'),                   # query params
      1 if any(x in url.lower() for x in ['bit.ly','tinyurl']) else 0  # shortened URL
   ]
   return features
