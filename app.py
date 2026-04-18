from flask import Flask, render_template, request
import pickle
import pandas as pd
import re
import string
import math
from urllib.parse import urlparse
import validators 

app = Flask(__name__)

#Load Artifacts
MODEL_FILE = 'XGBoost_model.pkl'
LABEL_ENCODER_FILE = 'label_encoder.pkl'

with open(MODEL_FILE, 'rb') as f:
    model = pickle.load(f)

with open(LABEL_ENCODER_FILE, 'rb') as f:
    label_encoder = pickle.load(f)

print(f"✅ Loaded model: {MODEL_FILE}")

# Get expected feature names directly from model
EXPECTED_FEATURES = getattr(model, "feature_names_in_", [])

# Suspicious keywords for phishing detection
suspicious_keywords = [
    'login', 'signin', 'verify', 'update', 'banking', 'account', 'secure',
    'ebay', 'paypal', 'apple', 'amazon', 'dropbox', 'drive', 'onedrive',
    'office', 'outlook', 'microsoft', 'cloud', 'confirm', 'password',
    'credential', 'support', 'service', 'security', 'webscr', 'transfer',
    'refund', 'alert', 'bill', 'invoice', 'gift', 'prize', 'lottery'
]

# Common TLDs list
COMMON_TLDS = ['com', 'org', 'net', 'edu', 'gov', 'info', 'biz', 'in', 'uk', 'io', 'co']

#Utility Functions
def shannon_entropy(s):
    """Calculate Shannon entropy of string s."""
    if not s:
        return 0
    probs = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log(p, 2) for p in probs])

def safe_urlparse(url):
    """Parse URL safely (avoid invalid IPv6 errors)."""
    if not isinstance(url, str):
        return urlparse('')
    url = url.strip().replace(' ', '')
    url = re.sub(r'[\[\]]', '', url)
    try:
        return urlparse(url)
    except Exception:
        return urlparse('')

#Feature Extraction
def extract_features(url: str):
    features = {}

    parsed = safe_urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    scheme = parsed.scheme.lower()
    full_url = url.lower()

    # BASIC FEATURES
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['query_length'] = len(query)

    # CHARACTER COUNTS
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_letters'] = sum(c.isalpha() for c in url)
    features['num_special_chars'] = sum(c in string.punctuation for c in url)
    features['num_dashes'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_dots'] = url.count('.')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_at'] = url.count('@')
    features['num_percent'] = url.count('%')
    features['num_ampersand'] = url.count('&')
    features['num_hash'] = url.count('#')

    # DOMAIN FEATURES
    features['num_subdomains'] = domain.count('.') - 1 if '.' in domain else 0
    features['has_ip'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain)))
    features['has_www'] = int('www' in domain)
    features['has_https'] = int('https' in scheme)
    features['starts_with_http'] = int(url.startswith('http'))
    features['ends_with_slash'] = int(url.endswith('/'))
    features['is_common_tld'] = int(domain.split('.')[-1] in COMMON_TLDS)
    features['tld_length'] = len(domain.split('.')[-1]) if '.' in domain else 0

    # KEYWORD FEATURES
    features['has_suspicious_word'] = int(any(word in full_url for word in suspicious_keywords))
    features['has_login_word'] = int(any(k in full_url for k in ['login', 'signin']))
    features['has_bank_word'] = int('bank' in full_url)
    features['has_paypal_word'] = int('paypal' in full_url)
    features['has_password_word'] = int('password' in full_url)

    # STRUCTURAL FEATURES
    features['num_params'] = url.count('&') + url.count('=')
    features['num_fragments'] = url.count('#')
    features['num_redirects'] = url.count('//') - 1
    features['has_encoded_chars'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    features['repeated_chars'] = int(bool(re.search(r'(.)\1{3,}', url)))

    tokens = [tok for tok in re.split('[./?=-]', url) if tok]
    features['shortest_token_len'] = min([len(tok) for tok in tokens] or [0])
    features['longest_token_len'] = max([len(tok) for tok in tokens] or [0])
    features['avg_token_len'] = sum(len(tok) for tok in tokens) / len(tokens) if tokens else 0

    # ENTROPY FEATURES
    features['url_entropy'] = shannon_entropy(url)
    features['domain_entropy'] = shannon_entropy(domain)
    features['path_entropy'] = shannon_entropy(path)

    # BOOLEAN / HEURISTIC
    features['contains_mailto'] = int('mailto:' in url)
    features['contains_double_slash_in_path'] = int('//' in path)
    features['has_long_domain'] = int(len(domain) > 30)
    features['has_long_path'] = int(len(path) > 40)
    features['is_short_url'] = int(any(shortener in full_url for shortener in [
        'bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly'
    ]))

    # RATIO FEATURES
    features['digit_ratio'] = features['num_digits'] / len(url) if len(url) else 0
    features['special_char_ratio'] = features['num_special_chars'] / len(url) if len(url) else 0
    features['letter_ratio'] = features['num_letters'] / len(url) if len(url) else 0
    features['subdomain_ratio'] = features['num_subdomains'] / (features['num_dots'] + 1) if (features['num_dots'] + 1) else 0

    df = pd.DataFrame([features])

    # Align features with model
    for col in EXPECTED_FEATURES:
        if col not in df.columns:
            df[col] = 0
    df = df.reindex(columns=EXPECTED_FEATURES, fill_value=0)

    return df

#Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url')

    # Empty input check
    if not url:
        return render_template('index.html', prediction_text="❌ Please enter a URL.")

    # 🔹 URL format validation
    if not validators.url(url):
        return render_template('index.html', prediction_text="⚠️ Invalid URL format. Example: https://google.com/phish")

    X_new = extract_features(url)

    try:
        y_pred = model.predict(X_new)[0]
        label = label_encoder.inverse_transform([y_pred])[0]

        confidence = None
        if hasattr(model, 'predict_proba'):
            prob = model.predict_proba(X_new)[0]
            confidence = round(max(prob) * 100, 2)

        return render_template(
            'index.html',
            url=url,
            prediction_text=f"🔍 Prediction: {label}",
            confidence=confidence
        )

    except Exception as e:
        return render_template('index.html', prediction_text=f"⚠️ Error: {str(e)}")

if __name__ == '__main__':
    app.run(debug=True)
