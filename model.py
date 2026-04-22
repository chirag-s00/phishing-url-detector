import pandas as pd

df1 = pd.read_csv(r"top-1m.csv",header=None)
df1 = df1.sample(5000, random_state=42)
df1.columns=['Rank','URL']
df1 = df1[['URL']]
df1['Label'] = 0

df2 = pd.read_csv(r"phishing_site_urls.csv")
df2 = df2.sample(5000, random_state=42)
df2['Label'] = 1

df1 = df1.dropna()
df2 = df2.dropna()
df1 = df1.drop_duplicates(subset=['URL'])
df2 = df2.drop_duplicates(subset=['URL'])



df = pd.concat([df1, df2],ignore_index=True)
df.shape

df = df.sample(frac=1,random_state=42).reset_index(drop=True)
df = df.drop_duplicates(subset=['URL'])

import re
import math
from urllib.parse import urlparse

def entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])

def extract_url_features(url):
    url = str(url)

    if not url.startswith("http"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_slashes": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "digit_ratio": sum(c.isdigit() for c in url) / len(url),
        "has_ip": int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))),
        "has_suspicious_tld": int(domain.endswith(("xyz","tk","ml","ga","cf","top","work","click","info"))),
        "domain_length": len(domain),
        "num_subdomains": domain.count("."),
        "has_https": int(url.startswith("https")),
        "path_length": len(parsed.path),
        "entropy": entropy(url),
        "num_query_params": len(parsed.query.split("&")) if parsed.query else 0
    }

df_features = pd.DataFrame(df['URL'].apply(extract_url_features).tolist())
df = pd.concat([df_features, df['Label']], axis=1)

X = df.drop([
    'Label',], axis=1)
feature_columns = X.columns
y = df['Label']




from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)



from sklearn.ensemble import RandomForestClassifier

model = RandomForestClassifier(
    n_estimators=200,
    class_weight='balanced',
    random_state=42
)

model.fit(X_train, y_train)



from sklearn.metrics import classification_report, accuracy_score

y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

def predict_url(url):
    features = extract_url_features(url)
    features_df = pd.DataFrame([features])
    features_df = features_df.reindex(columns=feature_columns, fill_value=0)

    pred = model.predict(features_df)[0]
    return "Phishing" if pred == 1 else "Legitimate"

def clean_domain(url):
    domain = urlparse(url).netloc.lower()
    domain = domain.replace("www.", "")
    return domain

import whois
from urllib.parse import urlparse
from datetime import datetime

from datetime import datetime, timezone

def domain_features(url):
    try:
        domain = urlparse(url).netloc.lower().replace("www.", "")

        w = whois.whois(domain)
        creation_date = w.creation_date

        # Handle list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Ensure it's datetime
        if not isinstance(creation_date, datetime):
            return {"domain_age_days": -1}

        # Convert both to same timezone (VERY IMPORTANT)
        now = datetime.now(timezone.utc)
        age = (now - creation_date).days

        return {"domain_age_days": age}

    except Exception as e:
        return {"domain_age_days": -1}

def final_predict(url):
    ml_result = predict_url(url)

    whois_data = domain_features(url)
    age = whois_data["domain_age_days"]

    if age != -1 and age < 30:
        return f"Phishing (New Domain: {age} days)"

    if age == -1:
        return f"{ml_result} (WHOIS unavailable.Could be phishing.)"

    return f"{ml_result} (Domain age: {age})"

import sys

if __name__ == "__main__":
    if len(sys.argv) > 1:
        url = sys.argv[1]
        print(final_predict(url))
    else:
        print("Usage: python detection_model.py <URL>")