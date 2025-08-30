import streamlit as st
import joblib
import pandas as pd
import json
from urllib.parse import urlparse, parse_qs
import re

# Load model and feature columns at app startup (ensure these files are in project root)
model = joblib.load("phish_rf.joblib")
with open("feature_columns.json") as f:
    feature_columns = json.load(f)

# Known legitimate domains whitelist
WHITELIST_DOMAINS = [
    "paypal.com", "paytm.com", "google.com", "microsoft.com", "amazon.com",
    "apple.com", "wikipedia.org"
]

def extract_features(url):
    features = {feat: 0 for feat in feature_columns}
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse('')

    domain = parsed.netloc or ''
    path = parsed.path or ''
    query = parsed.query or ''

    features["UrlLength"] = len(url)
    features["HostnameLength"] = len(domain)
    features["PathLength"] = len(path)
    features["QueryLength"] = len(query)
    features["NumDots"] = domain.count('.')
    features["SubdomainLevel"] = max(0, domain.count('.') - 1)
    features["NumDashInHostname"] = domain.count('-')
    features["NumDash"] = url.count('-')
    features["NumUnderscore"] = url.count('_')
    features["NumPercent"] = url.count('%')
    features["NumQueryComponents"] = len(parse_qs(query))
    features["NumAmpersand"] = url.count('&')
    features["NumHash"] = url.count('#')
    features["NumNumericChars"] = len(re.findall(r'\d', url))
    features["AtSymbol"] = 1 if "@" in url else 0
    features["TildeSymbol"] = 1 if "~" in url else 0
    features["NoHttps"] = 0 if parsed.scheme == "https" else 1
    features["IpAddress"] = 1 if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", domain) else 0
    features["PathLevel"] = path.count('/')
    features["DoubleSlashInPath"] = 1 if "//" in path else 0

    suspicious_words = [
        "login", "secure", "account", "update", "verify", "webscr",
        "signin", "bank", "confirm", "password"
    ]
    url_lower = url.lower()
    features["NumSensitiveWords"] = sum(word in url_lower for word in suspicious_words)

    zero_features = [
        "RandomString", "DomainInSubdomains", "DomainInPaths", "HttpsInHostname",
        "PctExtHyperlinks", "PctExtResourceUrls", "ExtFavicon", "InsecureForms",
        "RelativeFormAction", "ExtFormAction", "AbnormalFormAction",
        "PctNullSelfRedirectHyperlinks", "FrequentDomainNameMismatch",
        "FakeLinkInStatusBar", "RightClickDisabled", "PopUpWindow",
        "SubmitInfoToEmail", "IframeOrFrame", "MissingTitle", "ImagesOnlyInForm",
        "SubdomainLevelRT", "UrlLengthRT", "PctExtResourceUrlsRT",
        "AbnormalExtFormActionR", "ExtMetaScriptLinkRT",
        "PctExtNullSelfRedirectHyperlinksRT"
    ]
    for feat in zero_features:
        features[feat] = 0

    return features

def heuristic_score(url, features):
    score = 0
    if features["AtSymbol"] == 1:
        score += 3
    if features["NoHttps"] == 1:
        score += 3
    if features["NumSensitiveWords"] > 0:
        score += features["NumSensitiveWords"] * 2
    if features["IpAddress"] == 1:
        score += 4
    if features["DoubleSlashInPath"] == 1:
        score += 2
    if features["NumDots"] > 5:
        score += 2
    if features["NumDash"] > 3:
        score += 2
    return score

def is_whitelisted_domain(url):
    domain = urlparse(url).netloc.lower()
    for legit_domain in WHITELIST_DOMAINS:
        if domain == legit_domain or domain.endswith("." + legit_domain):
            return True
    return False

# Streamlit app UI
st.title("Phishing URL Detector")

# Sidebar author info
st.sidebar.markdown("""
### About Author  
**Khalid Naufal**  
[LinkedIn Profile](https://www.linkedin.com/in/khalid-naufal-ba467a278)  
""")

url = st.text_input("Enter a URL to check for phishing:")

if st.button("Check URL"):
    if url:
        features = extract_features(url)
        df = pd.DataFrame([features], columns=feature_columns)
        prediction = model.predict(df)[0]
        score = heuristic_score(url, features)

        if (
            prediction == 1
            or score >= 4
            or (("paypal" in url.lower() or "paytm" in url.lower()) and not is_whitelisted_domain(url))
            or features["NumSensitiveWords"] > 0
        ):
            st.error(f"🚨 PHISHING detected: {url}")
        else:
            st.success(f"✅ The URL appears LEGITIMATE: {url}")
    else:
        st.warning("Please enter a URL.")
