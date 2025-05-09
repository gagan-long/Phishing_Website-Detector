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
import os

# --- Custom CSS for Modern Look ---
st.markdown("""
<style>
body {
    background-color: #f0f2f6;
}
.stButton>button {
    background-color: #ff4b4b;
    color: white;
    font-weight: bold;
    border-radius: 8px;
    padding: 10px 24px;
    border: none;
    transition: background-color 0.3s ease;
}
.stButton>button:hover {
    background-color: #d73737;
}
.metric-container {
    background: white;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0 4px 8px rgba(0,0,0,0.07);
    margin-bottom: 20px;
    text-align: center;
}
.details-list, .paths-list, .ports-list {
    background: white;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0 4px 8px rgba(0,0,0,0.07);
    max-height: 300px;
    overflow-y: auto;
    margin-bottom: 24px;
}
.details-list ul, .paths-list ul, .ports-list ul {
    padding-left: 18px;
}
</style>
""", unsafe_allow_html=True)

# --- Blacklist Data ---
def load_blacklist():
    try:
        with open('blacklist.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []
    except Exception:
        return []

def save_blacklist(blacklist):
    with open('blacklist.json', 'w') as f:
        json.dump(blacklist, f, indent=2)

blacklisted_domains = load_blacklist()

def add_to_blacklist(domain):
    """Add a domain to the blacklist and save if not already present."""
    blacklist = load_blacklist()
    if domain not in blacklist:
        blacklist.append(domain)
        save_blacklist(blacklist)
        st.info(f"Domain {domain} has been added to the blacklist.")

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
        details['is_blacklisted'] = 'Yes' if domain in load_blacklist() else 'No'
    except Exception as e:
        details['error'] = str(e)
    return details

# --- Port Scan Feature ---
def port_scan(target, port_range=(1, 1024), max_threads=100):
    open_ports = []
    target_ip = None
    try:
        target_ip = socket.gethostbyname(target)
    except Exception:
        return [], "Could not resolve domain to IP."
    def scan_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            result = s.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
        except:
            pass
        finally:
            s.close()
    threads = []
    for port in range(port_range[0], port_range[1]+1):
        t = ThreadPoolExecutor(max_workers=max_threads)
        t.submit(scan_port, port)
        t.shutdown(wait=True)
    return sorted(open_ports), None

def main():
    st.markdown("<h1 style='color:#ff4b4b;'>🛡️ Phishing Website Detector</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#31333f;font-size:1.1rem;'>Analyze any website for phishing risk, sensitive directories, and more!</p>", unsafe_allow_html=True)
    url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
    port_scan_enabled = st.checkbox("Perform Port Scan (for open ports)", value=False)
    port_range = (1, 1024)
    if port_scan_enabled:
        colp1, colp2 = st.columns(2)
        with colp1:
            port_start = st.number_input("Port range start", min_value=1, max_value=65535, value=1)
        with colp2:
            port_end = st.number_input("Port range end", min_value=1, max_value=65535, value=1024)
        port_range = (int(port_start), int(port_end))
    if st.button("Analyze"):
        if url:
            with st.spinner("Analyzing website..."):
                details = extract_details(url)
                risk_score = calculate_risk_score(details)
                if risk_score > 50:
                    prediction = "🔴 Highly Likely Phishing"
                    pred_color = "#dc3545"
                elif risk_score > 30:
                    prediction = "🟡 Likely Phishing"
                    pred_color = "#ffc107"
                else:
                    prediction = "🟢 Potentially Safe"
                    pred_color = "#28a745"
                st.subheader("Analysis Results")
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"<div class='metric-container'><h3>Risk Score</h3><p style='font-size: 2rem; font-weight: bold;'>{risk_score}/100</p></div>", unsafe_allow_html=True)
                with col2:
                    st.markdown(f"<div class='metric-container'><h3>Prediction</h3><p style='font-size: 2rem; font-weight: bold; color: {pred_color};'>{prediction}</p></div>", unsafe_allow_html=True)
                st.subheader("Technical Details")
                st.markdown("<div class='details-list'><ul>", unsafe_allow_html=True)
                for key, value in details.items():
                    if key != 'found_paths':
                        st.markdown(f"<li><strong>{key}:</strong> {value}</li>", unsafe_allow_html=True)
                st.markdown("</ul></div>", unsafe_allow_html=True)
                st.subheader("Discovered Paths")
                if details.get('found_paths'):
                    st.markdown("<div class='paths-list'><ul>", unsafe_allow_html=True)
                    for path in details['found_paths']:
                        st.markdown(f"<li><code>{url.rstrip('/')}{path}</code></li>", unsafe_allow_html=True)
                    st.markdown("</ul></div>", unsafe_allow_html=True)
                else:
                    st.warning("No common paths discovered")
                # --- Port Scan Section ---
                if port_scan_enabled:
                    st.subheader(f"Port Scan Results ({port_range[0]}–{port_range[1]})")
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc
                    with st.spinner("Scanning ports... (this may take a while)"):
                        open_ports, error = port_scan(domain, port_range)
                    if error:
                        st.error(error)
                    elif open_ports:
                        st.markdown("<div class='ports-list'><ul>", unsafe_allow_html=True)
                        for port in open_ports:
                            st.markdown(f"<li><strong>Port {port}:</strong> <span style='color:green;'>OPEN</span></li>", unsafe_allow_html=True)
                        st.markdown("</ul></div>", unsafe_allow_html=True)
                    else:
                        st.info("No open ports found in the specified range.")
                st.subheader("Feedback")
                feedback = st.radio("Was this prediction accurate?", ("Yes", "No"), horizontal=True)
                comments = st.text_area("Additional Comments")
                if st.button("Submit Feedback"):
                    st.success("Thank you for your feedback! (Submitted: {})".format(feedback))
                    if feedback == "No":
                        parsed_url = urlparse(url)
                        domain = parsed_url.netloc
                        add_to_blacklist(domain)
        else:
            st.warning("Please enter a valid URL")

if __name__ == "__main__":
    main()
