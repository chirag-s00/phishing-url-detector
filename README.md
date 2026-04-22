# URL Phishing Detection
A model that is used to detect whether a URL is **Phishing or Legitimate** using Random Forest Classifer along with WHOIS domain age analysis.

## Overview
Phishing attacks usually rely on visual deception and the manipulation of URLs. This model parses the given URL to detect any suspicious parts.

### Key Features
- URL-based feature extraction (length, digits, entropy, etc.)
- Random Forest classification model
- WHOIS domain age integration

### Algorithm Used
The model uses a Random Forest classifier, an ensemble learning algorithm that combines multiple decision trees to improve prediction accuracy and reduce overfitting.

## Dataset

The datasets used in this project are not included in the repository due to size constraints.

Please download them manually:

- Legitimate URLs dataset (Tranco Top 1M): https://tranco-list.eu  
- Phishing URLs dataset (Kaggle): https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls

After downloading, place the files in the project directory.
Make sure the filenames match exactly:
- `top-1m.csv`
- `phishing_site_urls.csv`

Otherwise, update the file paths in the script accordingly.

## ⚙️ Setup

### 1. Clone the repository
```bash
git clone https://github.com/your-username/phishing-url-detector.git
cd phishing-url-detector

pip install -r requirements.txt

python detection_model.py https://example.com
```
## Conclusion
The model achieves high accuracy on structured datasets but may face generalization issues in real-world scenarios. This highlights the limitations of relying solely on URL-based features for phishing detection.

# Disclaimer
- This Model is made for Educational Purposes only.
- It should not be used as a standalone system for real-world phishing detection.
- WHOIS data might not be available for all URLs.
