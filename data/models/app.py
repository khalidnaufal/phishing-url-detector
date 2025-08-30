from flask import Flask, request, render_template
import joblib
import pandas as pd
import json
from urllib.parse import urlparse, parse_qs
import re

app = Flask(__name__)

# Load model and features once at startup
model = joblib.load("phish_rf.joblib")
with open("feature_columns.json") as f:
    feature_columns = json.load(f)

# Known legitimate domains for brand whitelist (expand as needed)
WHITELIST_DOMAINS = [
    "paypal.com", "paytm.com", "google.com", "microsoft.com", "amazon.com", "apple.com", "wikipedia.org"
]

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

    # Fill zero for unavailable features to match model input shape
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
    # Check if URL ends with any whitelisted domain exactly
    domain = urlparse(url).netloc.lower()
    for legit_domain in WHITELIST_DOMAINS:
        if domain == legit_domain or domain.endswith("." + legit_domain):
            return True
    return False

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url_input")
        if url:
            features = extract_features(url)
            df = pd.DataFrame([features], columns=feature_columns)
            prediction = model.predict(df)[0]
            score = heuristic_score(url, features)

            # Enhanced decision logic for phishing
            if (
                prediction == 1
                or score >= 4
                or (("paypal" in url.lower() or "paytm" in url.lower()) and not is_whitelisted_domain(url))
                or features["NumSensitiveWords"] > 0
            ):
                result = f"🚨 PHISHING: {url}"
            else:
                result = f"✅ LEGITIMATE: {url}"
    return render_template("index.html", result=result, url=url)

if __name__ == "__main__":
    app.run(debug=True)
