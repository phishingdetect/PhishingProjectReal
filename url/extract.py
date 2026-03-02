import re

def extract_urls(text):
    pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(pattern, text)