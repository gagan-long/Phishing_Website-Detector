Phishing Website Detector
A powerful, interactive Streamlit app to analyze and detect potential phishing websites. The app checks for suspicious patterns, verifies SSL and WHOIS info, crawls for common sensitive paths, and checks against a customizable blacklist.

Features
Phishing Risk Analysis: Scores any website URL for phishing risk based on technical and content factors.

Blacklist Checking: Instantly flags known malicious domains using a customizable blacklist.json.

Directory & File Crawling: Scans for common sensitive directories and files (e.g., /admin/, /login/, robots.txt).

WHOIS & SSL Checks: Displays domain age, registrar, and SSL certificate details.

Content Analysis: Detects login forms, sensitive info requests, and suspicious scripts.

User Feedback: Collects user feedback for continuous improvement.

Modern UI: Clean, responsive interface with Streamlit.

Demo
![Demo Screenshot](https://user-images.githubusercontent.com/yourusername/your-demo-image.png own screenshot!)*

Getting Started
1. Clone the Repository

git clone https://github.com/gagan-long/web_ditector_3.0.git cd  phishing-website-detector

2. Install Dependencies

pip install -r requirements.txt

3. Prepare Required Files
blacklist.json:
List of blacklisted domains. Example:

[
  "malicious-site.com",
  "phishing-example.org"
]

Or use the enhanced format:

{
  "domains": {
    "malicious-site.com": {
      "reason": "Known phishing campaign",
      "date_added": "2023-01-15",
      "severity": "high"
    }
  }
}

feedback.json:
(Optional) Will be created automatically to store user feedback.

.streamlit/config.toml:
(Optional, for custom theme)

[theme]
primaryColor = "#FF4B4B"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#31333F"
font = "sans serif"


4. Run the App

streamlit run app.py


Usage
Enter a URL (e.g., https://example.com) in the input box.

Click Analyze.

View the risk score, technical details, and discovered paths.

Optionally, submit feedback on the prediction.

Deployment
Deploy to Streamlit Community Cloud
Push your code to a public GitHub repository.

Go to Streamlit Cloud.

Click New app, select your repo and app.py.

Deploy!

Requirements
Python 3.8+

See requirements.txt for all dependencies:

streamlit

requests

beautifulsoup4

python-whois

tldextract

Security & Privacy
No user data is shared externally.

Blacklist and feedback are stored locally by default.

For production, consider using a secure database for feedback.

Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

License
MIT License

Acknowledgements
Streamlit

BeautifulSoup

python-whois

tldextract

Happy phishing detection! 🛡️