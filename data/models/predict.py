import joblib
import pandas as pd
import json
import os
from urllib.parse import urlparse, parse_qs
import re

print("Current working directory:", os.getcwd())

# Load trained model
model = joblib.load("../phish_rf.joblib")

# Load feature columns list
with open("../feature_columns.json") as f:
    feature_columns = json.load(f)

def extract_features(url):
    features = {feat: 0 for feat in feature_columns}
    try:
        parsed = urlparse(url)
    except:
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
    suspicious_words = ["login", "secure", "account", "update", "verify", "webscr",
                       "signin", "bank", "confirm", "password"]
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
    # Simple heuristic rules to increase phishing confidence
    if features["AtSymbol"] == 1:
        score += 2
    if features["NoHttps"] == 1:
        score += 2
    if features["NumSensitiveWords"] > 0:
        score += features["NumSensitiveWords"]
    if features["IpAddress"] == 1:
        score += 3
    if features["DoubleSlashInPath"] == 1:
        score += 1
    if features["NumDots"] > 5:
        score += 1
    if features["NumDash"] > 3:
        score += 1

    # Threshold for heuristic flag (adjustable)
    return score

url = input("Enter a URL to check: ")
features = extract_features(url)
df = pd.DataFrame([features], columns=feature_columns)
prediction = model.predict(df)[0]

score = heuristic_score(url, features)

print("Model prediction (0=legit, 1=phishing):", prediction)
print("Heuristic phishing score:", score)

# Combine both model and heuristic for final decision
if prediction == 1 or score >= 3:
    print(f"🚨 The URL '{url}' is likely PHISHING.")
else:
    print(f"✅ The URL '{url}' looks LEGITIMATE.")
