import streamlit as st
from urllib.parse import urlparse, urljoin
import re
import whois
import ssl
import requests
import socket
from bs4 import BeautifulSoup
import json
from concurrent.futures import ThreadPoolExecutor

# Load Blacklist Data
try:
    with open('blacklist.json', 'r') as f:
        blacklisted_domains = json.load(f)
except FileNotFoundError:
    blacklisted_domains = []

def calculate_risk_score(details):
    score = 0
    if details.get('has_at_symbol') == 'Yes':
        score += 5
    if details.get('url_length', 0) > 50:
        score += 10
    if details.get('uses_https') == 'No':
        score += 15
    if details.get('domain_age') == 'N/A':
        score += 10
    if details.get('has_ip_address') == 'Yes':
        score += 20
    if details.get('has_login_form') == 'Yes':
        score += 25
    if details.get('requests_sensitive_info') == 'Yes':
        score += 30
    if details.get('has_unusual_scripts') == 'Yes':
        score += 20
    return score

def crawl_website(target_url):
    base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
    session = requests.Session()
    found_paths = set(['/'])
    
    def check_path(path):
        try:
            full_url = urljoin(base_url, path)
            response = session.head(full_url, timeout=3, allow_redirects=True)
            if response.status_code < 400:
                return path
        except:
            return None
    
    common_dirs = [
        'admin', 'login', 'wp-admin', 'wp-content', 
        'images', 'css', 'js', 'assets', 'uploads',
        'backup', 'api', 'secret', 'private'
    ]
    
    common_files = [
        'robots.txt', 'sitemap.xml', 'config.php',
        '.env', 'package.json', 'web.config'
    ]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        dir_paths = [f"/{d}/" for d in common_dirs]
        found_paths.update(filter(None, executor.map(check_path, dir_paths)))
        
        file_paths = [f"/{f}" for f in common_files]
        found_paths.update(filter(None, executor.map(check_path, file_paths)))
    
    return sorted(found_paths)

def extract_details(url):
    details = {}
    try:
        parsed_url = urlparse(url)
        details['has_at_symbol'] = 'Yes' if '@' in url else 'No'
        details['url_length'] = len(url)
        details['found_paths'] = crawl_website(url)
        details['uses_https'] = 'Yes' if parsed_url.scheme == 'https' else 'No'

        domain = parsed_url.netloc
        try:
            w = whois.whois(domain)
            details['domain_age'] = str(w.creation_date)
            details['registrar'] = w.registrar if hasattr(w, 'registrar') else 'N/A'
        except Exception as e:
            details['whois_error'] = str(e)
            details['domain_age'] = 'N/A'
            details['registrar'] = 'N/A'

        if parsed_url.scheme == 'https':
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        details['ssl_issuer'] = str(cert.get('issuer', 'N/A'))
                        details['ssl_valid'] = str(cert.get('notAfter', 'N/A'))
            except Exception as e:
                details['ssl_error'] = str(e)
                details['ssl_issuer'] = 'N/A'
                details['ssl_valid'] = 'N/A'
        else:
            details['ssl_issuer'] = 'N/A'
            details['ssl_valid'] = 'N/A'

        try:
            response = requests.get(parsed_url.scheme + '://' + parsed_url.netloc + '/favicon.ico', timeout=5)
            details['has_favicon'] = 'Yes' if response.status_code == 200 else 'No'
        except Exception as e:
            details['favicon_error'] = str(e)
            details['has_favicon'] = 'No'

        details['has_ip_address'] = 'Yes' if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc) else 'No'
        details['is_long_url'] = 'Yes' if len(url) > 50 else 'No'
        details['has_unusual_chars'] = 'Yes' if re.search(r'[^a-zA-Z0-9\-\._~:\/\?#\[\]@!\$&\'\(\)\*\+\,\;\=]', url) else 'No'

        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            login_form = soup.find('form', {'action': re.compile(r'login', re.IGNORECASE)})
            details['has_login_form'] = 'Yes' if login_form else 'No'

            sensitive_info_patterns = [r'credit card', r'social security number', r'ssn', r'cvv']
            content = soup.get_text().lower()
            details['requests_sensitive_info'] = 'Yes' if any(re.search(pattern, content) for pattern in sensitive_info_patterns) else 'No'

            script_tags = soup.find_all('script')
            details['has_unusual_scripts'] = 'Yes' if any('eval(' in script.text for script in script_tags) else 'No'
        except Exception as e:
            details['content_error'] = str(e)
            details['has_login_form'] = 'N/A'
            details['requests_sensitive_info'] = 'N/A'
            details['has_unusual_scripts'] = 'N/A'
            
        details['is_blacklisted'] = 'Yes' if domain in blacklisted_domains else 'No'

    except Exception as e:
        details['error'] = str(e)
    return details

def main():
    st.title("Phishing Website Detector")
    url = st.text_input("Enter URL to analyze:")
    
    if st.button("Analyze"):
        if url:
            with st.spinner("Analyzing website..."):
                details = extract_details(url)
                risk_score = calculate_risk_score(details)
                
                if risk_score > 50:
                    prediction = "🔴 Highly Likely Phishing"
                elif risk_score > 30:
                    prediction = "🟡 Likely Phishing"
                else:
                    prediction = "🟢 Potentially Safe"

                st.subheader("Analysis Results")
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Risk Score", f"{risk_score}/100")
                with col2:
                    st.metric("Prediction", prediction)

                st.subheader("Technical Details")
                st.json(details, expanded=False)

                st.subheader("Discovered Paths")
                if details.get('found_paths'):
                    st.write("The following paths were found:")
                    for path in details['found_paths']:
                        st.code(f"{url.rstrip('/')}{path}", language="text")
                else:
                    st.warning("No common paths discovered")

                # Feedback system
                st.subheader("Feedback")
                feedback = st.radio("Was this prediction accurate?", ("Yes", "No"))
                if st.button("Submit Feedback"):
                    st.success(f"Thank you for your feedback! (Submitted: {feedback})")
                    # Add your feedback logging logic here
        else:
            st.warning("Please enter a valid URL")

if __name__ == "__main__":
    main()
