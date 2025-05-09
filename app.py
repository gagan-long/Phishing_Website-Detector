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
[data-testid="stAppViewContainer"] {
    background: linear-gradient(135deg, #f0f2f6 0%, #e9ecef 100%);
}
h1, h2, h3, h4 {
    color: #ff4b4b !important;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}
.stButton > button {
    background-color: #ff4b4b;
    color: #fff;
    font-weight: 600;
    border-radius: 8px;
    padding: 10px 28px;
    border: none;
    box-shadow: 0 2px 6px rgba(255,75,75,0.08);
    transition: background 0.2s, box-shadow 0.2s;
    font-size: 1.1rem;
}
.stButton > button:hover {
    background: #d73737;
    box-shadow: 0 4px 12px rgba(255,75,75,0.15);
}
.metric-container {
    background: #fff;
    border-radius: 12px;
    padding: 22px 18px 18px 18px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.07);
    margin-bottom: 22px;
    text-align: center;
    border-left: 6px solid #ff4b4b;
}
.metric-container h3 {
    color: #31333f;
    margin-bottom: 8px;
    font-size: 1.2rem;
    font-weight: 600;
}
.metric-container p {
    font-size: 2.1rem;
    font-weight: bold;
    margin: 0;
}
.details-list, .paths-list, .ports-list {
    background: #fff;
    border-radius: 12px;
    padding: 22px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.07);
    max-height: 320px;
    overflow-y: auto;
    margin-bottom: 26px;
    font-size: 1.04rem;
}
.details-list ul, .paths-list ul, .ports-list ul {
    padding-left: 22px;
    margin-bottom: 0;
}
.details-list li, .paths-list li, .ports-list li {
    margin-bottom: 8px;
}
.paths-list code, .ports-list code {
    background: #f8f9fa;
    color: #d6336c;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 1.02rem;
}
[data-testid="stRadio"], .stTextArea textarea {
    font-size: 1.08rem;
}
.stTextArea textarea {
    border-radius: 8px;
    border: 1.5px solid #ff4b4b;
    padding: 10px;
    background: #f8f9fa;
    font-family: inherit;
}
.stMarkdown h2, .stMarkdown h3, .stMarkdown h4 {
    color: #ff4b4b !important;
    font-weight: 700;
    margin-top: 18px;
}
.stAlert {
    border-radius: 10px !important;
    font-size: 1.04rem;
}
footer {visibility: hidden;}
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

def add_to_blacklist(domain):
    blacklist = load_blacklist()
    if domain not in blacklist:
        blacklist.append(domain)
        save_blacklist(blacklist)
        st.info(f"Domain {domain} has been added to the blacklist.")

# --- Typosquatting & Lookalike Detection ---
POPULAR_BRANDS = [
    "google.com", "facebook.com", "apple.com", "amazon.com", "microsoft.com",
    "paypal.com", "bankofamerica.com", "wellsfargo.com", "github.com", "twitter.com"
]

def generate_typos(domain):
    typos = set()
    if '.' in domain:
        name, tld = domain.rsplit('.', 1)
    else:
        name, tld = domain, ''
    # Missing dot
    typos.add(name.replace('.', '') + ('.' + tld if tld else ''))
    # Swapped adjacent letters
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
        typos.add(''.join(swapped) + ('.' + tld if tld else ''))
    # Missing letter
    for i in range(len(name)):
        typos.add(name[:i] + name[i+1:] + ('.' + tld if tld else ''))
    return typos

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

        # --- Typosquatting & lookalike detection ---
        domain_lower = domain.lower()
        typos = generate_typos(domain_lower)
        lookalike_matches = []
        for brand in POPULAR_BRANDS:
            brand_base = brand.lower()
            if (domain_lower == brand_base or
                domain_lower.replace('www.', '') == brand_base or
                brand_base in typos):
                lookalike_matches.append(brand)
        details['lookalike_brands'] = lookalike_matches if lookalike_matches else None

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
    closed_ports = []
    target_ip = None
    try:
        target_ip = socket.gethostbyname(target)
    except Exception:
        return [], [], "Could not resolve domain to IP."
    def scan_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            result = s.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)
        except:
            closed_ports.append(port)
        finally:
            s.close()
    threads = []
    for port in range(port_range[0], port_range[1]+1):
        t = ThreadPoolExecutor(max_workers=max_threads)
        t.submit(scan_port, port)
        t.shutdown(wait=True)
    return sorted(open_ports), sorted(closed_ports), None

# --- Text/Message Analysis Feature ---
def analyze_text(text):
    phishing_keywords = [
        "urgent", "verify your account", "update your information", "click here", "password", "login", "bank", "account suspended",
        "security alert", "unusual activity", "confirm", "reset", "limited time", "act now", "win", "free", "prize", "invoice"
    ]
    url_pattern = r'(https?://[^\s]+)'
    found_keywords = [kw for kw in phishing_keywords if kw in text.lower()]
    found_links = re.findall(url_pattern, text)
    found_brands = [brand for brand in POPULAR_BRANDS if brand.split('.')[0] in text.lower()]
    risk_score = len(found_keywords)*10 + len(found_links)*15 + len(found_brands)*20
    if risk_score > 100:
        risk_score = 100
    if risk_score > 50:
        risk_label = "🔴 Highly Likely Phishing"
    elif risk_score > 30:
        risk_label = "🟡 Likely Phishing"
    else:
        risk_label = "🟢 Potentially Safe"
    return {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "keywords": found_keywords,
        "links": found_links,
        "brands": found_brands
    }

def main():
    st.markdown("<h1 style='color:#ff4b4b;'>🛡️ Phishing Website Detector, Port & Text Scanner</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#31333f;font-size:1.1rem;'>Analyze a website, suspicious text, or message for phishing risk!</p>", unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["🔗 Website/Domain Analysis", "✉️ Text/Message Analysis"])

    # --- Website/Domain Tab ---
    with tab1:
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
        if st.button("Analyze", key="analyze_url"):
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
                        if key not in ['found_paths', 'lookalike_brands']:
                            st.markdown(f"<li><strong>{key}:</strong> {value}</li>", unsafe_allow_html=True)
                    st.markdown("</ul></div>", unsafe_allow_html=True)

                    st.subheader("Typosquatting & Lookalike Domain Check")
                    if details.get('lookalike_brands'):
                        st.warning(f"This domain is a lookalike or typo of: {', '.join(details['lookalike_brands'])}")
                    else:
                        st.success("No lookalike or typosquatting detected for popular brands.")

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
                            open_ports, closed_ports, error = port_scan(domain, port_range)
                            if error:
                                st.error(error)
                            else:
                                st.markdown("<div class='ports-list'><ul>", unsafe_allow_html=True)
                                if open_ports:
                                    st.markdown("<li><strong>Open Ports:</strong></li>", unsafe_allow_html=True)
                                    for port in open_ports:
                                        st.markdown(f"<li style='margin-left:20px;'><strong>Port {port}:</strong> <span style='color:green;'>OPEN</span></li>", unsafe_allow_html=True)
                                if closed_ports:
                                    st.markdown("<li><strong>Closed Ports:</strong></li>", unsafe_allow_html=True)
                                    for port in closed_ports[:20]:
                                        st.markdown(f"<li style='margin-left:20px;'><strong>Port {port}:</strong> <span style='color:red;'>CLOSED</span></li>", unsafe_allow_html=True)
                                    if len(closed_ports) > 20:
                                        st.markdown(f"<li style='margin-left:20px;'><em>...and {len(closed_ports)-20} more closed ports</em></li>", unsafe_allow_html=True)
                                st.markdown("</ul></div>", unsafe_allow_html=True)
                    st.subheader("Feedback")
                    feedback = st.radio("Was this prediction accurate?", ("Yes", "No"), horizontal=True)
                    comments = st.text_area("Additional Comments")
                    if st.button("Submit Feedback", key="feedback_url"):
                        st.success("Thank you for your feedback! (Submitted: {})".format(feedback))
                        if feedback == "No":
                            parsed_url = urlparse(url)
                            domain = parsed_url.netloc
                            add_to_blacklist(domain)
            else:
                st.warning("Please enter a valid URL")

    # --- Text/Message Tab ---
    with tab2:
        st.write("Paste any suspicious email, SMS, or message below to check for phishing risk.")
        text = st.text_area("Paste your message or email here:", height=180)
        if st.button("Analyze Text", key="analyze_text"):
            if text.strip():
                result = analyze_text(text)
                st.subheader("Text Analysis Results")
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"<div class='metric-container'><h3>Risk Score</h3><p style='font-size: 2rem; font-weight: bold;'>{result['risk_score']}/100</p></div>", unsafe_allow_html=True)
                with col2:
                    color = "#dc3545" if "Highly" in result['risk_label'] else "#ffc107" if "Likely" in result['risk_label'] else "#28a745"
                    st.markdown(f"<div class='metric-container'><h3>Prediction</h3><p style='font-size: 2rem; font-weight: bold; color: {color};'>{result['risk_label']}</p></div>", unsafe_allow_html=True)
                st.subheader("Detected Issues")
                if result['keywords']:
                    st.warning(f"Phishing keywords detected: {', '.join(result['keywords'])}")
                else:
                    st.success("No phishing keywords detected.")
                if result['links']:
                    st.warning(f"Suspicious links found: {', '.join(result['links'])}")
                else:
                    st.success("No suspicious links found.")
                if result['brands']:
                    st.warning(f"Brand names detected: {', '.join(result['brands'])}")
                else:
                    st.info("No popular brand names detected.")
            else:
                st.info("Paste some text to analyze.")

if __name__ == "__main__":
    main()
