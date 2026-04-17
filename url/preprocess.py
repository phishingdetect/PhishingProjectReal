import requests
from bs4 import BeautifulSoup


# 1. PII Filtering (login, password, forms...)
def pii_filter(url):
    try:
        response = requests.get(url, timeout=5)
        text = response.text.lower()

        keywords = ["login", "sign in", "password", "verify", "account", "bank"]

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        # check if page has forms + sensitive keywords
        if forms and any(word in text for word in keywords):
            return True  # suspicious page (collects PII)
        else:
            return False  # not likely phishing target

    except:
        return False


# 2. Simple Blacklist Check
def blacklist_check(url):
    blacklist = ["phishing.com", "malicious.com", "fakebank.com"]

    for bad in blacklist:
        if bad in url:
            return True
    return False


# 3. Redirect Resolution
def resolve_redirects(url):
    try:
        response = requests.get(url, timeout=5)
        return response.url  # final redirected URL
    except:
        return url