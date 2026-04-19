import os
import re
from urllib.parse import urljoin

import requests
import pandas as pd
from bs4 import BeautifulSoup

# Load phishing URL dataset once
DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "DataFiles", "phishurls.csv")

try:
    phishing_data = pd.read_csv(DATA_PATH, header=None)
    phishing_urls = set(phishing_data[0].astype(str).str.strip().str.lower())
except:
    phishing_urls = set()


def pii_filter(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        html = response.text
        text = html.lower()

        pii_phrases = [
            "login", "log in", "sign in", "signin", "sign-on", "sign on",
            "user id", "username", "email", "email address", "email or phone",
            "mobile number", "phone number", "account", "my account",
            "access your account", "password", "enter password",
            "forgot password", "reset password", "recover account", "verify",
            "verify your identity", "verification", "confirm",
            "confirm your identity", "security challenge", "security code",
            "security info", "one-time code", "otp", "passcode", "pin",
            "bank", "banking", "online banking", "billing", "payment",
            "card number", "credit card", "debit card", "cvv", "authenticate"
        ]

        soup = BeautifulSoup(html, "html.parser")
        has_form = len(soup.find_all("form")) > 0

        popup_markers = ["alert(", "prompt(", "confirm("]
        has_popup = any(marker in text for marker in popup_markers)

        has_pii_phrase = any(phrase in text for phrase in pii_phrases)

        return has_pii_phrase and (has_form or has_popup)
    except:
        return False


def debug_pii_filter(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        html = response.text
        text = html.lower()

        pii_phrases = [
            "login", "log in", "sign in", "signin", "sign-on", "sign on",
            "user id", "username", "email", "email address", "email or phone",
            "mobile number", "phone number", "account", "my account",
            "access your account", "password", "enter password",
            "forgot password", "reset password", "recover account", "verify",
            "verify your identity", "verification", "confirm",
            "confirm your identity", "security challenge", "security code",
            "security info", "one-time code", "otp", "passcode", "pin",
            "bank", "banking", "online banking", "billing", "payment",
            "card number", "credit card", "debit card", "cvv", "authenticate"
        ]

        soup = BeautifulSoup(html, "html.parser")
        has_form = len(soup.find_all("form")) > 0

        popup_markers = ["alert(", "prompt(", "confirm("]
        has_popup = any(marker in text for marker in popup_markers)

        matched_phrases = [p for p in pii_phrases if p in text]

        return {
            "has_form": has_form,
            "has_popup": has_popup,
            "matched_phrases": matched_phrases,
            "is_pii_page": bool(matched_phrases and (has_form or has_popup))
        }
    except Exception as e:
        return {"error": str(e)}


def blacklist_check(url):
    try:
        normalized = url.strip().lower().rstrip("/")

        if normalized in phishing_urls:
            return True

        if (normalized + "/") in phishing_urls:
            return True

        for bad_url in phishing_urls:
            bad = str(bad_url).strip().lower().rstrip("/")
            if normalized == bad:
                return True

        return False
    except:
        return False


def resolve_redirects(url):
    try:
        current_url = url
        visited = set()

        for _ in range(5):  # limit to avoid infinite loops
            if current_url in visited:
                break
            visited.add(current_url)

            # 1) Server-side redirects + short-to-long expansion
            response = requests.get(current_url, timeout=5, allow_redirects=True)
            final_url = response.url
            html = response.text

            # Server redirect or short URL expansion
            if final_url != current_url:
                current_url = final_url
                continue

            # 2) HTML Meta refresh redirects
            soup = BeautifulSoup(html, "html.parser")
            meta = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)})
            if meta and meta.get("content"):
                match = re.search(r'url\s*=\s*([^;]+)', meta["content"], re.I)
                if match:
                    redirected_url = match.group(1).strip().strip('"').strip("'")
                    current_url = urljoin(current_url, redirected_url)
                    continue

            # 3) JavaScript redirects
            js_patterns = [
                r'window\.location\s*=\s*[\'"]([^\'"]+)[\'"]',
                r'window\.location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
                r'location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
                r'location\.replace\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
            ]

            found_js_redirect = False
            for pattern in js_patterns:
                match = re.search(pattern, html, re.I)
                if match:
                    redirected_url = match.group(1).strip()
                    current_url = urljoin(current_url, redirected_url)
                    found_js_redirect = True
                    break

            if found_js_redirect:
                continue

            # No more redirects, this is the final URL
            return current_url

        return current_url

    except:
        return url