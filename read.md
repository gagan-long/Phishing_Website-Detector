🛡️ Phishing Website Detector
[![Python](https://img.shields.io/badge/pythmlit](https://img.shields.io/badge/built%20with-Streaense: MIT](https://img.shields.io/badge/License-MIT-yellowrful, interactive Streamlit app to analyze and detect potential phishing websites.
The app checks for suspicious patterns, verifies SSL and WHOIS info, crawls for common sensitive paths, checks against a customizable blacklist, and leverages multiple live threat intelligence feeds.

📑 Table of Contents
Features

Demo

Getting Started

Usage

Deployment

Requirements

Security & Privacy

Contributing

License

Acknowledgements

🚀 Features
Phishing Risk Analysis: Scores any website URL for phishing risk based on technical and content factors.

Blacklist Checking: Instantly flags known malicious domains using a customizable blacklist.json.

Multi-Feed Threat Intelligence: One-click update of your blacklist from PhishTank, OpenPhish, and URLhaus.

Directory & File Crawling: Scans for common sensitive directories and files (e.g., /admin/, /login/, robots.txt).

WHOIS & SSL Checks: Displays domain age, registrar, and SSL certificate details, including certificate transparency and age warnings.

Content & DOM Analysis: Detects login forms, sensitive info requests, suspicious scripts, and advanced DOM clues (forms, password fields, suspicious keywords).

Website Screenshot: Takes and displays a live screenshot of the analyzed site.

VirusTotal Integration: Checks URL reputation with VirusTotal (API key required, stored securely in .env).

User Feedback & Community Reporting: Collects user feedback, supports community voting on domains (phishing/safe), and displays a community verdict.

Phishing Awareness Quiz: Interactive self-test tab to educate users on phishing detection.

Export Data: Download your blacklist and community votes for further analysis.

Modern UI: Clean, responsive interface with Streamlit.

🖼️ Demo
![Demo Screenshot](https://user-images.githubusercontent.com/yourusername/your-demo-image.png your own screenshot!</i></sub>

🏁 Getting Started
1. Clone the Repository
bash
git clone https://github.com/gagan-long/web_ditector_3.0.git
cd web_ditector_3.0
2. Install Dependencies
bash
pip install -r requirements.txt
3. Prepare Required Files
blacklist.json
List of blacklisted domains. Example:

json
[
  "malicious-site.com",
  "phishing-example.org"
]
Or use the enhanced format:

json
{
  "domains": {
    "malicious-site.com": {
      "reason": "Known phishing campaign",
      "date_added": "2023-01-15",
      "severity": "high"
    }
  }
}
.env
For VirusTotal integration, add your API key:

text
VT_API_KEY=your_virustotal_api_key
feedback.json and community_votes.json
(Optional) Created automatically to store user feedback and community votes.

.streamlit/config.toml
(Optional, for custom theme)

text
[theme]
primaryColor = "#FF4B4B"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#31333F"
font = "sans serif"
4. Run the App
bash
streamlit run app.py
💡 Usage
Enter a URL (e.g., https://example.com) in the input box.

Click Analyze.

View the risk score, technical details, discovered paths, screenshot, and threat intelligence verdicts.

Optionally, submit feedback, report domains as phishing/safe, or take the phishing awareness quiz.

Use the Update Blacklist from Threat Feeds button to fetch the latest domains from multiple open feeds.

Download your blacklist or community reports for external use.

🚀 Deployment
Deploy to Streamlit Community Cloud
Push your code to a public GitHub repository.

Go to Streamlit Cloud.

Click New app, select your repo and app.py.

Deploy!

⚙️ Requirements
Python 3.8+

Chrome/Chromium (for screenshot and DOM analysis)

See requirements.txt for all dependencies:

streamlit

requests

beautifulsoup4

python-whois

tldextract

selenium

webdriver-manager

pillow

python-dotenv

🔒 Security & Privacy
No user data is shared externally.

Blacklist, feedback, and community votes are stored locally by default.

For production, consider using a secure database for feedback and votes.

Never commit your .env file or API keys to public repositories.

🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

📄 License
MIT License

🙏 Acknowledgements
Streamlit

BeautifulSoup

python-whois

tldextract

Selenium

VirusTotal

PhishTank

OpenPhish

URLhaus

Happy phishing detection! 🛡️

<sub>Inspired by Best-README-Template and Real Python’s README Guide.</sub>