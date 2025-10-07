import streamlit as st
import wikipedia
import streamlit_authenticator as stauth
import requests
import pandas as pd
import base64, time
import plotly.express as px
import plotly.graph_objects as go
import re
import random

# --------------------------
# PAGE CONFIGURATION
# --------------------------
st.set_page_config(
    page_title="Sentinel-Auth",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --------------------------
# ENHANCED CUSTOM CSS
# --------------------------
st.markdown("""
<style>
    /* Main Background Gradient */
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    
    /* Homepage Styles */
    .homepage-header {
        font-size: 4rem;
        color: white;
        text-align: center;
        margin-bottom: 1rem;
        font-weight: bold;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .homepage-subheader {
        font-size: 1.5rem;
        color: #f0f0f0;
        text-align: center;
        margin-bottom: 3rem;
        font-weight: 300;
    }
    
    .feature-card {
        background: rgba(255, 255, 255, 0.95);
        border-radius: 20px;
        padding: 30px;
        margin: 15px 0;
        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        border: 1px solid rgba(255,255,255,0.3);
        transition: transform 0.3s ease;
    }
    
    .feature-card:hover {
        transform: translateY(-5px);
    }
    
    .feature-icon {
        font-size: 3rem;
        margin-bottom: 15px;
        text-align: center;
    }
    
    .feature-title {
        font-size: 1.5rem;
        color: #2e86ab;
        margin-bottom: 10px;
        text-align: center;
        font-weight: bold;
    }
    
    .feature-description {
        color: #666;
        text-align: center;
        line-height: 1.6;
    }
    
    .get-started-btn {
        background: linear-gradient(45deg, #FF6B6B, #FFE66D);
        color: white;
        padding: 15px 40px;
        border-radius: 50px;
        border: none;
        font-size: 1.2rem;
        font-weight: bold;
        cursor: pointer;
        box-shadow: 0 5px 15px rgba(255,107,107,0.4);
        transition: all 0.3s ease;
        display: block;
        margin: 30px auto;
    }
    
    .get-started-btn:hover {
        transform: scale(1.05);
        box-shadow: 0 8px 25px rgba(255,107,107,0.6);
    }
    
    /* Login Page Styles */
    .login-container {
        background: rgba(255, 255, 255, 0.95);
        border-radius: 20px;
        padding: 40px;
        margin: 50px auto;
        max-width: 500px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
    }
    
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: bold;
    }
    
    .section-header {
        font-size: 2rem;
        color: #2e86ab;
        border-bottom: 3px solid #2e86ab;
        padding-bottom: 0.5rem;
        margin-bottom: 1.5rem;
        font-weight: bold;
    }
    
    .success-box {
        background: linear-gradient(135deg, #d4edda, #c3e6cb);
        border: 2px solid #28a745;
        border-radius: 15px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 5px 15px rgba(40,167,69,0.2);
    }
    
    .warning-box {
        background: linear-gradient(135deg, #fff3cd, #ffeaa7);
        border: 2px solid #ffc107;
        border-radius: 15px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 5px 15px rgba(255,193,7,0.2);
    }
    
    .danger-box {
        background: linear-gradient(135deg, #f8d7da, #f5c6cb);
        border: 2px solid #dc3545;
        border-radius: 15px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 5px 15px rgba(220,53,69,0.2);
    }
    
    .info-box {
        background: linear-gradient(135deg, #d1ecf1, #bee5eb);
        border: 2px solid #17a2b8;
        border-radius: 15px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 5px 15px rgba(23,162,184,0.2);
    }
    
    .prevention-box {
        background: linear-gradient(135deg, #e8f5e8, #d4edda);
        border: 2px solid #28a745;
        border-radius: 15px;
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 5px 15px rgba(40,167,69,0.2);
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 20px;
        padding: 25px;
        color: white;
        text-align: center;
        margin: 10px 0;
        box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        transition: transform 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
    }
    
    .tip-card {
        background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%);
        border-radius: 15px;
        padding: 20px;
        color: white;
        margin: 10px 0;
        box-shadow: 0 5px 15px rgba(255,154,158,0.3);
    }
    
    /* Chat message styles */
    .user-message {
        background: linear-gradient(135deg, #e3f2fd, #bbdefb);
        border: 2px solid #2196f3;
        border-radius: 20px;
        padding: 15px;
        margin: 10px 0;
        box-shadow: 0 3px 10px rgba(33,150,243,0.2);
    }
    
    .bot-message {
        background: linear-gradient(135deg, #f3e5f5, #e1bee7);
        border: 2px solid #9c27b0;
        border-radius: 20px;
        padding: 15px;
        margin: 10px 0;
        box-shadow: 0 3px 10px rgba(156,39,176,0.2);
    }
</style>
""", unsafe_allow_html=True)

# --------------------------
# HASHED PASSWORDS
# --------------------------
hashed_passwords = stauth.Hasher(["admin123", "user123"]).generate()
credentials = {
    "usernames": {
        "admin": {"name": "Administrator", "password": hashed_passwords[0]},
        "bhavya": {"name": "Bhavya", "password": hashed_passwords[1]},
    }
}

# --------------------------
# AUTHENTICATOR
# --------------------------
authenticator = stauth.Authenticate(
    credentials,
    "threat_app",
    "abcdef",
    cookie_expiry_days=1,
)

# --------------------------
# PREVENTION MODULE FUNCTIONS
# --------------------------
class ThreatPrevention:
    @staticmethod
    def analyze_password_strength(password):
        """AI-based password strength analysis"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("❌ Password should be at least 8 characters long")
        
        # Complexity checks
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("❌ Add uppercase letters")
            
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("❌ Add lowercase letters")
            
        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("❌ Add numbers")
            
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("❌ Add special characters")
        
        # Common password check
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
        if password.lower() in common_passwords:
            score = 0
            feedback.append("🚨 This is a commonly used password!")
        
        # Strength assessment
        if score >= 5:
            strength = "💪 Very Strong"
            color = "green"
        elif score >= 3:
            strength = "👍 Strong"
            color = "blue"
        elif score >= 2:
            strength = "⚠️ Moderate"
            color = "orange"
        else:
            strength = "🚨 Weak"
            color = "red"
            
        return strength, feedback, score, color

    @staticmethod
    def generate_secure_password(length=12):
        """Generate AI-suggested secure password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def check_phishing_indicators(email_text):
        """AI-based phishing detection in email/text"""
        indicators = {
            "urgency": len(re.findall(r'urgent|immediately|quick|action required', email_text, re.IGNORECASE)),
            "suspicious_links": len(re.findall(r'http://|https?://[^\s]+', email_text)),
            "personal_info_requests": len(re.findall(r'password|account|login|verify|confirm', email_text, re.IGNORECASE)),
            "suspicious_sender": len(re.findall(r'bank|paypal|amazon|microsoft', email_text, re.IGNORECASE)),
            "grammar_errors": len(re.findall(r'\b(?:pleasse|urgentt|acount|securty)\b', email_text, re.IGNORECASE))
        }
        
        total_score = sum(indicators.values())
        
        if total_score >= 4:
            return "🚨 High phishing risk detected!", indicators, "red"
        elif total_score >= 2:
            return "⚠️ Moderate phishing risk detected!", indicators, "orange"
        else:
            return "✅ Low phishing risk", indicators, "green"

    @staticmethod
    def get_security_recommendations(threat_type):
        """AI-powered security recommendations"""
        recommendations = {
            "phishing": [
                "Enable two-factor authentication on all accounts",
                "Verify sender email addresses before clicking links",
                "Use email filtering software",
                "Educate team members about phishing signs",
                "Report suspicious emails to your IT department"
            ],
            "malware": [
                "Keep antivirus software updated",
                "Regularly update operating systems and applications",
                "Avoid downloading from untrusted sources",
                "Use a firewall and intrusion detection system",
                "Backup important data regularly"
            ],
            "weak_password": [
                "Use password managers to generate and store strong passwords",
                "Enable biometric authentication where available",
                "Implement password expiration policies",
                "Use passphrases instead of passwords",
                "Monitor for password breaches regularly"
            ],
            "network": [
                "Use VPN for remote connections",
                "Implement network segmentation",
                "Regular security audits and penetration testing",
                "Monitor network traffic for anomalies",
                "Use encrypted communication protocols"
            ],
            "social_media": [
                "Review privacy settings regularly",
                "Limit personal information sharing",
                "Be cautious of friend requests from strangers",
                "Use different passwords for social accounts",
                "Enable login notifications"
            ],
            "data_breach": [
                "Monitor dark web for compromised data",
                "Change passwords immediately after breach",
                "Enable credit monitoring if financial data exposed",
                "Notify relevant authorities and users",
                "Conduct security audit to identify vulnerabilities"
            ]
        }
        return recommendations.get(threat_type, ["No specific recommendations available."])

    @staticmethod
    def analyze_network_security(network_type, security_protocol, devices_connected, remote_access, guest_network):
        """Analyze network security configuration"""
        security_score = 85  # Base score
        
        # Adjust score based on inputs
        if security_protocol == "WPA3":
            security_score += 15
        elif security_protocol == "WPA2":
            security_score += 10
        elif security_protocol in ["WPA", "WEP"]:
            security_score -= 10
        else:  # Open
            security_score -= 30
        
        if remote_access:
            security_score -= 5
        if guest_network:
            security_score += 5
            
        # Generate recommendations
        recommendations = []
        if security_protocol in ["WPA", "WEP", "Open"]:
            recommendations.append("🚨 Upgrade to WPA2 or WPA3 encryption immediately")
        
        if devices_connected > 20:
            recommendations.append("⚠️ Consider network segmentation for many devices")
        
        if remote_access:
            recommendations.append("🔒 Review and secure remote access configurations")
        
        if not recommendations:
            recommendations.append("✅ Your network configuration appears secure")
            
        return security_score, recommendations

    @staticmethod
    def analyze_social_media_security(checks):
        """Analyze social media security based on checklist"""
        score = sum(checks) * 100 // len(checks) if checks else 0
        
        recommendations = []
        if score < 80:
            if not checks[0]:  # strong_password
                recommendations.append("🔑 Use a strong, unique password for this platform")
            if not checks[1]:  # two_factor
                recommendations.append("📱 Enable two-factor authentication for extra security")
            if not checks[2]:  # private_profile
                recommendations.append("👤 Set your profile to private to control visibility")
            if not checks[3]:  # location_off
                recommendations.append("📍 Disable location sharing to protect your privacy")
            if not checks[4]:  # review_tags
                recommendations.append("🏷️ Enable tag review to control your online presence")
            if not checks[5]:  # limited_data
                recommendations.append("🔒 Limit data sharing with third-party apps")
        else:
            recommendations.append("✅ Your social media security settings are excellent!")
            
        return score, recommendations

# --------------------------
# HOMEPAGE
# --------------------------
def show_homepage():
    """Display beautiful homepage before login"""
    st.markdown('<div class="homepage-header">🛡️ Sentinel-Auth</div>', unsafe_allow_html=True)
    st.markdown('<div class="homepage-subheader">Advanced AI-Powered Threat Detection & Prevention System</div>', unsafe_allow_html=True)
    
    # Features Grid
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🔒</div>
            <div class="feature-title">Real-time Threat Detection</div>
            <div class="feature-description">
                Advanced URL scanning with VirusTotal API integration. 
                Detect malicious websites and prevent cyber attacks before they happen.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🤖</div>
            <div class="feature-title">AI Wikipedia Assistant</div>
            <div class="feature-description">
                Intelligent chatbot powered by Wikipedia. 
                Get instant answers and research assistance for cybersecurity topics.
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🛡️</div>
            <div class="feature-title">Proactive Prevention</div>
            <div class="feature-description">
                Comprehensive threat prevention tools including password analysis, 
                phishing detection, and network security scanning.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">📊</div>
            <div class="feature-title">Data Analytics</div>
            <div class="feature-description">
                Visualize cybersecurity data with interactive charts and 
                gain insights into attack patterns and security trends.
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🔍</div>
            <div class="feature-title">Network Security</div>
            <div class="feature-description">
                Scan your network configurations for vulnerabilities 
                and get personalized security recommendations.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">📱</div>
            <div class="feature-title">Social Media Protection</div>
            <div class="feature-description">
                Audit your social media security settings and 
                protect your online presence from privacy threats.
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Get Started Button
    if st.button("🚀 Get Started - Secure Login", key="get_started", use_container_width=True):
        st.session_state.show_login = True
        st.rerun()

# --------------------------
# MAIN APPLICATION FLOW
# --------------------------
def main():
    # Initialize session state
    if 'show_login' not in st.session_state:
        st.session_state.show_login = False
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    # Show homepage if not logged in and not showing login
    if not st.session_state.logged_in and not st.session_state.show_login:
        show_homepage()
        return
    
    # Show login page if requested
    if not st.session_state.logged_in and st.session_state.show_login:
        show_login_page()
        return
    
    # Show main application if logged in
    show_main_application()

def show_login_page():
    """Display login page"""
    st.markdown("""
    <div class="login-container">
        <div class="main-header">🛡️ Sentinel-Auth</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Login form in the centered container
    with st.container():
        name, authentication_status, username = authenticator.login(
            fields={"form_name": "Login", "username": "Username", "password": "Password", "login": "Login"}, 
            location="main"
        )
        
        # Back to homepage button
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if st.button("← Back to Homepage", use_container_width=True):
                st.session_state.show_login = False
                st.rerun()
        
        if authentication_status:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.name = name
            st.rerun()
        elif authentication_status is False:
            st.error("❌ Username/password is incorrect")
        elif authentication_status is None:
            st.warning("ℹ️ Please enter your username and password")

def show_main_application():
    """Display main application after login"""
    # Sidebar with better styling
    with st.sidebar:
        st.success(f"🎉 Welcome, **{st.session_state.name}**!")
        authenticator.logout("🚪 Logout", "sidebar")
        
        st.markdown("---")
        st.markdown("### 🧭 Navigation")
        section = st.radio(
            "Choose your section:",
            ["📚 Wikipedia Chatbot", "🛡️ Security Tools", "🛡️ Threat Prevention", "📊 Data Visualization"],
            key="nav"
        )
        
        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.info("""
        **Sentinel-Auth** is a comprehensive security system that combines:
        - Real-time URL scanning
        - Proactive threat prevention
        - Wikipedia AI chatbot
        - Cybersecurity analytics
        """)

    # Wikipedia Chatbot Section
    if section == "📚 Wikipedia Chatbot":
        st.markdown('<div class="section-header">🤖 Wikipedia AI Assistant</div>', unsafe_allow_html=True)
        
        # Info box
        with st.container():
            st.markdown("""
            <div class="info-box">
            <h4>💡 How to use:</h4>
            <p>Ask me anything! I'll search Wikipedia and give you a concise summary.</p>
            </div>
            """, unsafe_allow_html=True)
        
        if "messages" not in st.session_state:
            st.session_state.messages = []

        def get_wikipedia_summary(query):
            try:
                results = wikipedia.search(query)
                if not results:
                    return "Sorry, I couldn't find anything on that topic."
                summary = wikipedia.summary(results[0], sentences=3, auto_suggest=False, redirect=True)
                return summary
            except wikipedia.DisambiguationError as e:
                return f"Your query is ambiguous, did you mean: {', '.join(e.options[:5])}?"
            except wikipedia.PageError:
                return "Sorry, I couldn't find a page matching your query."
            except Exception:
                return "Oops, something went wrong."

        # Chat interface
        col1, col2 = st.columns([3, 1])
        with col1:
            user_input = st.text_input("💬 Ask me anything:", placeholder="Type your question here...")
        with col2:
            st.write("")  # Spacing
            st.write("")
            ask_button = st.button("🔍 Search", use_container_width=True)

        if ask_button and user_input:
            with st.spinner("🔍 Searching Wikipedia..."):
                st.session_state.messages.append({"role": "user", "content": user_input})
                bot_response = get_wikipedia_summary(user_input)
                st.session_state.messages.append({"role": "bot", "content": bot_response})

        # Display chat messages with better styling
        for msg in st.session_state.messages:
            if msg["role"] == "user":
                st.markdown(f"""
                <div class="user-message">
                    <strong>👤 You:</strong> {msg['content']}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="bot-message">
                    <strong>🤖 Choco:</strong> {msg['content']}
                </div>
                """, unsafe_allow_html=True)

    # Security Tools Section
    elif section == "🛡️ Security Tools":
        st.markdown('<div class="section-header">🔒 Security Scanner</div>', unsafe_allow_html=True)
        
        # Metrics cards
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>🛡️ Real-time</h3>
                <h2>URL Scanner</h2>
                <p>VirusTotal API Powered</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <h3>⚡ Instant</h3>
                <h2>Threat Analysis</h2>
                <p>Multiple Engine Check</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <h3>📊 Detailed</h3>
                <h2>Security Report</h2>
                <p>Comprehensive Results</p>
            </div>
            """, unsafe_allow_html=True)

        # URL Scanner
        with st.container():
            st.markdown("### 🌐 URL Safety Check")
            
            # Prefer to load from secrets.toml
            try:
                api_key = st.secrets["VIRUSTOTAL_API_KEY"]
            except KeyError:
                # fallback inline key not recommended for production
                api_key = "eb6f6caad9a31538ced27f970b3e790af750d2da03f98bae9f3cb0ef66a34d77"

            def check_url_safety(url):
                headers = {"x-apikey": api_key}
                # Submit URL for analysis
                resp = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=10
                )
                if resp.status_code not in (200, 201):
                    return None, f"API Error: {resp.status_code} - {resp.text}"

                analysis_id = resp.json().get("data", {}).get("id")
                if not analysis_id:
                    return None, "Could not retrieve analysis ID."

                # Poll analysis status
                analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                start = time.time()
                while True:
                    r = requests.get(analysis_endpoint, headers=headers, timeout=10)
                    if r.status_code != 200:
                        return None, f"API Error: {r.status_code} - {r.text}"
                    data = r.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        # Check verdict
                        stats = data["data"]["attributes"].get("stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        if malicious > 0 or suspicious > 0:
                            return False, data  # unsafe
                        else:
                            return True, data   # safe
                    if time.time() - start > 12:  # timeout
                        break
                    time.sleep(1)

                # fallback: fetch cached report using base64 URL id
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                report = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
                if report.status_code == 200:
                    data = report.json()
                    stats = data["data"]["attributes"].get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    if malicious > 0 or suspicious > 0:
                        return False, data
                    else:
                        return True, data
                return None, f"Final API error: {report.status_code}"

            url_input = st.text_input("Enter URL to scan:", placeholder="https://example.com")
            scan_col1, scan_col2 = st.columns([1, 4])
            with scan_col1:
                scan_button = st.button("🔍 Scan URL", use_container_width=True)
            
            if scan_button:
                if not url_input:
                    st.error("❌ Please enter a URL.")
                elif not (url_input.startswith("http://") or url_input.startswith("https://")):
                    st.error("❌ URL must start with http:// or https://")
                else:
                    with st.spinner("🛡️ Scanning URL with multiple antivirus engines..."):
                        safe, details = check_url_safety(url_input)
                    
                    if safe is None:
                        st.markdown(f"""
                        <div class="warning-box">
                            <h4>⚠️ Scan Error</h4>
                            <p>{details}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    elif safe:
                        st.markdown("""
                        <div class="success-box">
                            <h4>✅ This URL is Safe!</h4>
                            <p>No malicious activity detected by security engines.</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div class="danger-box">
                            <h4>🚨 Malicious URL Detected!</h4>
                            <p>This URL has been flagged by security engines as potentially dangerous.</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # Show detailed results in expander
                    with st.expander("📋 View Detailed Scan Report"):
                        st.json(details)

    # THREAT PREVENTION SECTION
    elif section == "🛡️ Threat Prevention":
        st.markdown('<div class="section-header">🛡️ Threat Prevention</div>', unsafe_allow_html=True)
        
        # Enhanced Prevention Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>🔐 Password</h3>
                <h2>Strength Analyzer</h2>
                <p>Security Assessment</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <h3>🎣 Phishing</h3>
                <h2>Detection System</h2>
                <p>Email Security Analysis</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <h3>🔍 Network</h3>
                <h2>Security Scanner</h2>
                <p>Vulnerability Check</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="metric-card">
                <h3>📱 Social</h3>
                <h2>Media Protection</h2>
                <p>Privacy Audit</p>
            </div>
            """, unsafe_allow_html=True)

        # EXPANDED Prevention Tools in Tabs
        prev_tab1, prev_tab2, prev_tab3, prev_tab4, prev_tab5 = st.tabs([
            "🔐 Password Security", 
            "🎣 Phishing Detection", 
            "🔍 Network Security",
            "📱 Social Media",
            "💡 Security Recommendations"
        ])
        
        with prev_tab1:
            st.subheader("Password Strength Analyzer")
            
            col1, col2 = st.columns([2, 1])
            with col1:
                password = st.text_input("Enter password to analyze:", type="password", 
                                       placeholder="Type your password here...", key="pw_analyzer")
                analyze_btn = st.button("🔍 Analyze Password", use_container_width=True, key="analyze_btn")
            
            with col2:
                st.write("")
                st.write("")
                generate_btn = st.button("🎲 Generate Secure Password", use_container_width=True, key="generate_btn")
            
            if generate_btn:
                secure_pass = ThreatPrevention.generate_secure_password()
                st.session_state.generated_password = secure_pass
                st.markdown(f"""
                <div class="success-box">
                    <h4>✅ Generated Secure Password:</h4>
                    <code style='font-size: 1.2em; background: #f0f0f0; padding: 10px; border-radius: 5px;'>{secure_pass}</code>
                    <p><small>Copy this password and store it securely!</small></p>
                </div>
                """, unsafe_allow_html=True)
            
            if analyze_btn and password:
                strength, feedback, score, color = ThreatPrevention.analyze_password_strength(password)
                
                # Display strength result
                st.markdown(f"<h3 style='color: {color};'>Password Strength: {strength}</h3>", unsafe_allow_html=True)
                
                # Progress bar for visual indication
                progress_value = score / 5.0
                st.progress(progress_value)
                
                # Feedback
                if feedback:
                    st.subheader("🔍 Improvement Suggestions:")
                    for item in feedback:
                        st.write(item)
                else:
                    st.success("🎉 Excellent! Your password meets all security criteria!")
                
                # Security tips
                st.markdown("""
                <div class="tip-card">
                    <h4>💡 Password Security Tips:</h4>
                    <ul>
                        <li>Use at least 12 characters</li>
                        <li>Combine uppercase, lowercase, numbers & symbols</li>
                        <li>Avoid dictionary words and personal information</li>
                        <li>Use unique passwords for different accounts</li>
                        <li>Consider using a password manager</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)
        
        with prev_tab2:
            st.subheader("Phishing Detection")
            
            email_text = st.text_area(
                "Paste email/text content to analyze:",
                height=150,
                placeholder="Paste the suspicious email or message content here...",
                key="phishing_input"
            )
            
            if st.button("🔍 Analyze for Phishing", use_container_width=True, key="phishing_btn"):
                if email_text:
                    with st.spinner("Analyzing content for phishing indicators..."):
                        result, indicators, color = ThreatPrevention.check_phishing_indicators(email_text)
                    
                    st.markdown(f"<h3 style='color: {color};'>{result}</h3>", unsafe_allow_html=True)
                    
                    # Display detailed analysis
                    st.subheader("📊 Detailed Analysis:")
                    for indicator, count in indicators.items():
                        st.write(f"**{indicator.replace('_', ' ').title()}:** {count} instances")
                    
                    # Recommendations
                    if "High" in result or "Moderate" in result:
                        st.markdown("""
                        <div class="danger-box">
                            <h4>🚨 Immediate Actions Recommended:</h4>
                        """, unsafe_allow_html=True)
                        recommendations = ThreatPrevention.get_security_recommendations("phishing")
                        for rec in recommendations:
                            st.write(f"• {rec}")
                        st.markdown("</div>", unsafe_allow_html=True)
                else:
                    st.warning("Please enter some text to analyze.")

        # NETWORK SECURITY SCANNER
        with prev_tab3:
            st.subheader("🔍 Network Security Scanner")
            
            st.markdown("""
            <div class="info-box">
                <h4>🌐 Network Security Assessment</h4>
                <p>Scan your network for potential vulnerabilities and security issues.</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Network assessment form
            with st.form("network_scan"):
                col1, col2 = st.columns(2)
                
                with col1:
                    network_type = st.selectbox(
                        "Network Type:",
                        ["Home WiFi", "Office Network", "Public WiFi", "Enterprise Network"]
                    )
                    
                    devices_connected = st.slider(
                        "Number of connected devices:",
                        min_value=1, max_value=
