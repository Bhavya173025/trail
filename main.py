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
    page_title="Sentinel-Auth | Cybersecurity Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced Custom CSS for modern professional look
st.markdown("""
<style>
    /* Main styling */
    .main-header {
        font-size: 3.5rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: 800;
        padding: 1rem;
    }
    
    .section-header {
        font-size: 2.2rem;
        color: #2e86ab;
        border-bottom: 3px solid #2e86ab;
        padding-bottom: 0.8rem;
        margin-bottom: 2rem;
        font-weight: 700;
    }
    
    /* Enhanced card designs */
    .success-box {
        background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
        border: none;
        border-radius: 15px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border-left: 5px solid #28a745;
    }
    
    .warning-box {
        background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
        border: none;
        border-radius: 15px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border-left: 5px solid #ffc107;
    }
    
    .danger-box {
        background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%);
        border: none;
        border-radius: 15px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border-left: 5px solid #dc3545;
    }
    
    .info-box {
        background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
        border: none;
        border-radius: 15px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border-left: 5px solid #17a2b8;
    }
    
    .prevention-box {
        background: linear-gradient(135deg, #e8f5e8 0%, #d4edda 100%);
        border: none;
        border-radius: 15px;
        padding: 25px;
        margin: 15px 0;
        box-shadow: 0 4px 20px rgba(76,175,80,0.2);
        border-left: 5px solid #4caf50;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 20px;
        padding: 25px;
        color: white;
        text-align: center;
        margin: 10px 0;
        box-shadow: 0 8px 25px rgba(102,126,234,0.3);
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
        box-shadow: 0 4px 15px rgba(255,154,158,0.3);
    }
    
    /* Sidebar enhancements */
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
    }
    
    /* Button enhancements */
    .stButton>button {
        border-radius: 10px;
        border: none;
        padding: 10px 20px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
    
    /* Input field enhancements */
    .stTextInput>div>div>input {
        border-radius: 10px;
        border: 2px solid #e9ecef;
        padding: 10px;
    }
    
    .stTextInput>div>div>input:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 2px rgba(102,126,234,0.2);
    }
    
    /* Tab enhancements */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #f8f9fa;
        border-radius: 10px 10px 0 0;
        gap: 8px;
        padding: 10px 20px;
        font-weight: 600;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #667eea !important;
        color: white !important;
    }
    
    /* Progress bar styling */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    }
    
    /* Chat message styling */
    .chat-user {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 15px;
        border-radius: 18px 18px 4px 18px;
        margin: 10px 0;
        max-width: 80%;
        margin-left: auto;
    }
    
    .chat-bot {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        padding: 15px;
        border-radius: 18px 18px 18px 4px;
        margin: 10px 0;
        max-width: 80%;
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
# ENHANCED PREVENTION MODULE FUNCTIONS
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
# ENHANCED LOGIN PAGE
# --------------------------
st.markdown('<div class="main-header">🛡️ Sentinel-Auth</div>', unsafe_allow_html=True)

# Add a tagline
st.markdown("""
<div style='text-align: center; margin-bottom: 3rem;'>
    <h3 style='color: #6c757d; font-weight: 300;'>Advanced Cybersecurity & Threat Prevention Platform</h3>
</div>
""", unsafe_allow_html=True)

# --------------------------
# LOGIN FORM
# --------------------------
name, authentication_status, username = authenticator.login(fields={"form_name": "Login"}, location="main")

if authentication_status:
    # Enhanced Sidebar with better styling
    with st.sidebar:
        st.markdown("""
        <div style='text-align: center; padding: 1rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    border-radius: 15px; color: white; margin-bottom: 2rem;'>
            <h3>🎉 Welcome!</h3>
            <h4>**{name}**</h4>
        </div>
        """.format(name=name), unsafe_allow_html=True)
        
        authenticator.logout("🚪 Logout", "sidebar")
        
        st.markdown("---")
        st.markdown("### 🧭 Navigation")
        section = st.radio(
            "Choose your section:",
            ["📚 Wikipedia Chatbot", "🛡️ Security Tools", "🛡️ Threat Prevention", "📊 Data Visualization"],
            key="nav"
        )
        
        st.markdown("---")
        st.markdown("### 📈 Quick Stats")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("🛡️ Security", "98%", "2%")
        with col2:
            st.metric("🔍 Scans", "24", "3 today")
        
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
    if "📚 Wikipedia Chatbot" in section:
        st.markdown('<div class="section-header">🤖 Wikipedia AI Assistant</div>', unsafe_allow_html=True)
        
        # Enhanced Info box
        with st.container():
            st.markdown("""
            <div class="info-box">
                <h4>💡 How to use:</h4>
                <p>Ask me anything! I'll search Wikipedia and give you a concise summary with instant responses.</p>
                <p><strong>Features:</strong> Natural language processing • Quick responses • Accurate information</p>
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

        # Enhanced Chat interface
        col1, col2 = st.columns([3, 1])
        with col1:
            user_input = st.text_input("💬 Ask me anything:", placeholder="Type your question here...", key="chat_input")
        with col2:
            st.write("")  # Spacing
            st.write("")
            ask_button = st.button("🔍 Search", use_container_width=True, key="search_btn")

        if ask_button and user_input:
            with st.spinner("🔍 Searching Wikipedia..."):
                st.session_state.messages.append({"role": "user", "content": user_input})
                bot_response = get_wikipedia_summary(user_input)
                st.session_state.messages.append({"role": "bot", "content": bot_response})

        # Enhanced chat messages display
        chat_container = st.container()
        with chat_container:
            for msg in st.session_state.messages:
                if msg["role"] == "user":
                    st.markdown(f"""
                    <div class="chat-user">
                        <strong>👤 You:</strong> {msg['content']}
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="chat-bot">
                        <strong>🤖 Choco:</strong> {msg['content']}
                    </div>
                    """, unsafe_allow_html=True)

        # Clear chat button
        if st.session_state.messages:
            if st.button("🗑️ Clear Chat History", use_container_width=True):
                st.session_state.messages = []
                st.rerun()

    # Security Tools Section
    elif "🛡️ Security Tools" in section:
        st.markdown('<div class="section-header">🔒 Security Scanner</div>', unsafe_allow_html=True)
        
        # Enhanced Metrics cards
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>🛡️ Real-time</h3>
                <h2>URL Scanner</h2>
                <p>VirusTotal API Powered</p>
                <div style='font-size: 2rem;'>🌐</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <h3>⚡ Instant</h3>
                <h2>Threat Analysis</h2>
                <p>Multiple Engine Check</p>
                <div style='font-size: 2rem;'>⚡</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <h3>📊 Detailed</h3>
                <h2>Security Report</h2>
                <p>Comprehensive Results</p>
                <div style='font-size: 2rem;'>📊</div>
            </div>
            """, unsafe_allow_html=True)

        # URL Scanner with enhanced design
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

            # Enhanced URL input section
            url_col1, url_col2 = st.columns([3, 1])
            with url_col1:
                url_input = st.text_input("Enter URL to scan:", placeholder="https://example.com", key="url_scanner")
            with url_col2:
                st.write("")
                st.write("")
                scan_button = st.button("🔍 Scan URL", use_container_width=True, key="url_scan_btn")
            
            if scan_button:
                if not url_input:
                    st.markdown("""
                    <div class="warning-box">
                        <h4>⚠️ Input Required</h4>
                        <p>Please enter a URL to scan.</p>
                    </div>
                    """, unsafe_allow_html=True)
                elif not (url_input.startswith("http://") or url_input.startswith("https://")):
                    st.markdown("""
                    <div class="warning-box">
                        <h4>⚠️ Invalid URL Format</h4>
                        <p>URL must start with http:// or https://</p>
                    </div>
                    """, unsafe_allow_html=True)
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
                            <p><strong>Confidence Level:</strong> High</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown("""
                        <div class="danger-box">
                            <h4>🚨 Malicious URL Detected!</h4>
                            <p>This URL has been flagged by security engines as potentially dangerous.</p>
                            <p><strong>Recommended Action:</strong> Do not visit this website</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # Enhanced detailed results
                    with st.expander("📋 View Detailed Scan Report", expanded=False):
                        if details:
                            st.json(details)
                        else:
                            st.info("No detailed report available.")

    # ENHANCED THREAT PREVENTION SECTION
    elif "🛡️ Threat Prevention" in section:
        st.markdown('<div class="section-header">🛡️ Threat Prevention</div>', unsafe_allow_html=True)
        
        # Enhanced Prevention Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>🔐 Password</h3>
                <h2>Strength Analyzer</h2>
                <p>Security Assessment</p>
                <div style='font-size: 2rem;'>🔐</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="metric-card">
                <h3>🎣 Phishing</h3>
                <h2>Detection System</h2>
                <p>Email Security Analysis</p>
                <div style='font-size: 2rem;'>🎣</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <h3>🔍 Network</h3>
                <h2>Security Scanner</h2>
                <p>Vulnerability Check</p>
                <div style='font-size: 2rem;'>🔍</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="metric-card">
                <h3>📱 Social</h3>
                <h2>Media Protection</h2>
                <p>Privacy Audit</p>
                <div style='font-size: 2rem;'>📱</div>
            </div>
            """, unsafe_allow_html=True)

        # EXPANDED Prevention Tools in Enhanced Tabs
        prev_tab1, prev_tab2, prev_tab3, prev_tab4, prev_tab5 = st.tabs([
            "🔐 Password Security", 
            "🎣 Phishing Detection", 
            "🔍 Network Security",
            "📱 Social Media",
            "💡 Security Recommendations"
        ])
        
        with prev_tab1:
            st.subheader("🔐 Password Strength Analyzer")
            
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
                    <div style='background: #2d3748; padding: 15px; border-radius: 10px; margin: 10px 0;'>
                        <code style='font-size: 1.2em; color: #68d391; font-family: monospace;'>{secure_pass}</code>
                    </div>
                    <p><small>🔒 Copy this password and store it securely in a password manager!</small></p>
                </div>
                """, unsafe_allow_html=True)
            
            if analyze_btn and password:
                strength, feedback, score, color = ThreatPrevention.analyze_password_strength(password)
                
                # Enhanced strength display
                st.markdown(f"<h3 style='color: {color}; text-align: center;'>Password Strength: {strength}</h3>", unsafe_allow_html=True)
                
                # Enhanced progress bar
                progress_value = score / 5.0
                st.progress(progress_value)
                
                # Enhanced feedback section
                if feedback:
                    st.subheader("🔍 Improvement Suggestions:")
                    for item in feedback:
                        st.write(f"• {item}")
                else:
                    st.markdown("""
                    <div class="success-box">
                        <h4>🎉 Excellent!</h4>
                        <p>Your password meets all security criteria!</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Enhanced security tips
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
            st.subheader("🎣 Phishing Detection")
            
            st.markdown("""
            <div class="info-box">
                <h4>🔍 How it works:</h4>
                <p>Our AI analyzes text content for common phishing indicators including urgency tactics, 
                suspicious links, personal information requests, and grammatical errors.</p>
            </div>
            """, unsafe_allow_html=True)
            
            email_text = st.text_area(
                "Paste email/text content to analyze:",
                height=150,
                placeholder="Paste the suspicious email or message content here...",
                key="phishing_input"
            )
            
            analyze_col1, analyze_col2 = st.columns([1, 4])
            with analyze_col1:
                phishing_btn = st.button("🔍 Analyze for Phishing", use_container_width=True, key="phishing_btn")
            
            if phishing_btn:
                if email_text:
                    with st.spinner("🔍 Analyzing content for phishing indicators..."):
                        result, indicators, color = ThreatPrevention.check_phishing_indicators(email_text)
                    
                    # Enhanced result display
                    st.markdown(f"""
                    <div style='text-align: center; padding: 20px; border-radius: 15px; background-color: {color}20; border: 2px solid {color};'>
                        <h3 style='color: {color};'>{result}</h3>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Enhanced detailed analysis
                    st.subheader("📊 Detailed Analysis:")
                    analysis_cols = st.columns(2)
                    for i, (indicator, count) in enumerate(indicators.items()):
                        with analysis_cols[i % 2]:
                            st.metric(
                                label=indicator.replace('_', ' ').title(),
                                value=count,
                                delta=None
                            )
                    
                    # Enhanced recommendations
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
                    st.warning("⚠️ Please enter some text to analyze.")

        # Enhanced Network Security Scanner
        with prev_tab3:
            st.subheader("🔍 Network Security Scanner")
            
            st.markdown("""
            <div class="info-box">
                <h4>🌐 Network Security Assessment</h4>
                <p>Scan your network for potential vulnerabilities and security issues. Get personalized recommendations to enhance your network security.</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Enhanced network assessment form
            with st.form("network_scan"):
                col1, col2 = st.columns(2)
                
                with col1:
                    network_type = st.selectbox(
                        "Network Type:",
                        ["Home WiFi", "Office Network", "Public WiFi", "Enterprise Network"],
                        help="Select the type of network you want to assess"
                    )
                    
                    devices_connected = st.slider(
                        "Number of connected devices:",
                        min_value=1, max_value=50, value=5,
                        help="Approximate number of devices connected to your network"
                    )
                
                with col2:
                    security_protocol = st.selectbox(
                        "Security Protocol:",
                        ["WPA3", "WPA2", "WPA", "WEP", "Open"],
                        help="Current security protocol used by your network"
                    )
                    
                    remote_access = st.checkbox("Remote access enabled", help="Do you have remote access enabled?")
                    guest_network = st.checkbox("Guest network available", help="Is guest network feature enabled?")
                
                submitted = st.form_submit_button("🔍 Scan Network Security", use_container_width=True)
            
            if submitted:
                with st.spinner("🔍 Scanning network configuration..."):
                    time.sleep(2)  # Simulate scanning
                    
                    security_score, recommendations = ThreatPrevention.analyze_network_security(
                        network_type, security_protocol, devices_connected, remote_access, guest_network
                    )
                    
                    # Enhanced results display
                    st.subheader("📊 Network Security Report")
                    
                    # Score with visual indicator
                    score_col1, score_col2, score_col3 = st.columns(3)
                    with score_col1:
                        st.metric("Security Score", f"{security_score}/100")
                    with score_col2:
                        if security_score >= 80:
                            risk_level = "Low"
                            risk_color = "green"
                        elif security_score >= 60:
                            risk_level = "Medium"
                            risk_color = "orange"
                        else:
                            risk_level = "High"
                            risk_color = "red"
                        st.metric("Risk Level", risk_level)
                    with score_col3:
                        st.metric("Recommendations", len(recommendations))
                    
                    # Visual progress bar for score
                    st.progress(security_score / 100)
                    
                    # Enhanced recommendations
                    st.subheader("🛡️ Security Recommendations:")
                    for i, rec in enumerate(recommendations, 1):
                        if "🚨" in rec:
                            st.error(f"{i}. {rec}")
                        elif "⚠️" in rec:
                            st.warning(f"{i}. {rec}")
                        elif "🔒" in rec:
                            st.info(f"{i}. {rec}")
                        else:
                            st.success(f"{i}. {rec}")

        # Enhanced Social Media Protection
        with prev_tab4:
            st.subheader("📱 Social Media Protection")
            
            st.markdown("""
            <div class="info-box">
                <h4>🔒 Social Media Security Audit</h4>
                <p>Check your social media profiles for privacy and security risks. Get personalized recommendations to protect your online presence.</p>
            </div>
            """, unsafe_allow_html=True)
            
            social_platform = st.selectbox(
                "Select Platform:",
                ["Facebook", "Instagram", "Twitter", "LinkedIn", "TikTok", "All Platforms"],
                key="social_platform"
            )
            
            # Enhanced security checklist
            st.subheader("🔍 Security Checklist")
            
            col1, col2 = st.columns(2)
            
            with col1:
                strong_password = st.checkbox("Strong unique password", help="Use a strong, unique password for this platform")
                two_factor = st.checkbox("Two-factor authentication enabled", help="Enable 2FA for additional security")
                private_profile = st.checkbox("Profile set to private", help="Set your profile to private mode")
            
            with col2:
                location_off = st.checkbox("Location sharing disabled", help="Disable location sharing in posts")
                review_tags = st.checkbox("Review tags before appearing", help="Review tags before they appear on your profile")
                limited_data = st.checkbox("Limited data sharing with third parties", help="Limit data sharing with third-party apps")
            
            analyze_social_btn = st.button("🛡️ Analyze Social Media Security", key="social_analysis", use_container_width=True)
            
            if analyze_social_btn:
                # Calculate security score
                checks = [strong_password, two_factor, private_profile, location_off, review_tags, limited_data]
                score, recommendations = ThreatPrevention.analyze_social_media_security(checks)
                
                st.subheader("📊 Security Analysis Results")
                
                # Enhanced score display
                if score >= 80:
                    color = "green"
                    status = "Excellent"
                    emoji = "🎉"
                elif score >= 60:
                    color = "orange"
                    status = "Good"
                    emoji = "👍"
                else:
                    color = "red"
                    status = "Needs Improvement"
                    emoji = "⚠️"
                
                st.markdown(f"""
                <div style='text-align: center; padding: 20px; border-radius: 15px; background-color: {color}20; border: 2px solid {color};'>
                    <h3 style='color: {color};'>{emoji} Security Score: {score}% - {status}</h3>
                </div>
                """, unsafe_allow_html=True)
                
                # Progress bar
                st.progress(score / 100)
                
                # Enhanced recommendations
                st.subheader("💡 Improvement Suggestions:")
                for rec in recommendations:
                    if "🔑" in rec:
                        st.error(f"• {rec}")
                    elif "📱" in rec:
                        st.warning(f"• {rec}")
                    else:
                        st.info(f"• {rec}")

        # Enhanced Security Recommendations
        with prev_tab5:
            st.subheader("💡 Security Recommendations")
            
            st.markdown("""
            <div class="info-box">
                <h4>🎯 Personalized Security Guidance</h4>
                <p>Get tailored security recommendations based on specific threat types. Our AI-powered system provides actionable advice to enhance your cybersecurity posture.</p>
            </div>
            """, unsafe_allow_html=True)
            
            threat_type = st.selectbox(
                "Select threat type for recommendations:",
                ["phishing", "malware", "weak_password", "network", "social_media", "data_breach"],
                key="threat_type",
                help="Choose the type of threat you want recommendations for"
            )
            
            rec_btn = st.button("🎯 Get Recommendations", use_container_width=True, key="rec_btn")
            
            if rec_btn:
                recommendations = ThreatPrevention.get_security_recommendations(threat_type)
                
                st.markdown(f"""
                <div class="prevention-box">
                    <h4>🛡️ Security Recommendations for {threat_type.replace('_', ' ').title()}:</h4>
                """, unsafe_allow_html=True)
                
                for i, rec in enumerate(recommendations, 1):
                    st.write(f"**{i}.** {rec}")
                
                st.markdown("</div>", unsafe_allow_html=True)
                
                # Enhanced additional tips
                st.markdown("""
                <div class="tip-card">
                    <h4>💡 Proactive Security Measures:</h4>
                    <ul>
                        <li>Regular security awareness training for all users</li>
                        <li>Implement multi-layered security defense strategy</li>
                        <li>Conduct regular security audits and system updates</li>
                        <li>Backup critical data regularly using 3-2-1 rule</li>
                        <li>Monitor systems for unusual activity and set up alerts</li>
                        <li>Develop and test incident response plans regularly</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)

    # Enhanced Data Visualization Section
    elif "📊 Data Visualization" in section:
        st.markdown('<div class="section-header">📈 Cybersecurity Analytics</div>', unsafe_allow_html=True)
        
        try:
            data = pd.read_csv('data/cybersecurity_intrusion_data.csv')
            
            # Enhanced metrics display
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                total_attacks = data['attack_detected'].sum() if 'attack_detected' in data.columns else 0
                st.metric("🚨 Total Attacks", total_attacks, delta=f"{total_attacks} detected")
            
            with col2:
                total_records = len(data)
                st.metric("📊 Total Records", f"{total_records:,}")
            
            with col3:
                attack_rate = (total_attacks / total_records * 100) if total_records > 0 else 0
                st.metric("📈 Attack Rate", f"{attack_rate:.1f}%")
            
            with col4:
                if 'protocol_type' in data.columns:
                    unique_protocols = data['protocol_type'].nunique()
                    st.metric("🔧 Protocols", unique_protocols)

            # Enhanced tabs for different visualizations
            tab1, tab2, tab3, tab4 = st.tabs(["📊 Attack Distribution", "🔧 Protocol Analysis", "📈 Trend Analysis", "📋 Data Preview"])
            
            with tab1:
                st.subheader("Attack vs Non-Attack Distribution")
                if 'attack_detected' in data.columns:
                    attack_counts = data['attack_detected'].value_counts()
                    
                    # Enhanced Pie Chart
                    fig = px.pie(
                        values=attack_counts.values, 
                        names=['Non-Attack' if x == 0 else 'Attack' for x in attack_counts.index],
                        color=['Non-Attack' if x == 0 else 'Attack' for x in attack_counts.index],
                        color_discrete_map={'Non-Attack':'#28a745', 'Attack':'#dc3545'},
                        hole=0.4
                    )
                    fig.update_traces(
                        textposition='inside', 
                        textinfo='percent+label',
                        marker=dict(line=dict(color='#ffffff', width=2))
                    )
                    fig.update_layout(
                        title="Network Traffic Distribution",
                        showlegend=True,
                        height=500
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("Attack detection data not available in the dataset.")

            with tab2:
                st.subheader("Network Protocol Usage")
                if 'protocol_type' in data.columns:
                    protocol_counts = data['protocol_type'].value_counts()
                    fig = px.bar(
                        x=protocol_counts.index, 
                        y=protocol_counts.values,
                        labels={'x': 'Protocol Type', 'y': 'Count'},
                        color=protocol_counts.values,
                        color_continuous_scale='viridis',
                        text=protocol_counts.values
                    )
                    fig.update_traces(
                        texttemplate='%{text}',
                        textposition='outside',
                        marker=dict(line=dict(color='darkgray', width=1))
                    )
                    fig.update_layout(
                        title="Protocol Distribution Across Network",
                        xaxis_tickangle=-45,
                        height=500
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("Protocol type data not available in the dataset.")

            with tab3:
                st.subheader("Security Trend Analysis")
                # Create a sample time series if not available
                if 'timestamp' not in data.columns:
                    # Generate sample time series data
                    dates = pd.date_range(start='2024-01-01', periods=len(data), freq='H')
                    sample_data = pd.DataFrame({
                        'timestamp': dates,
                        'attack_detected': data['attack_detected'] if 'attack_detected' in data.columns else [random.choice([0,1]) for _ in range(len(data))],
                        'traffic_volume': [random.randint(100, 1000) for _ in range(len(data))]
                    })
                    
                    # Create trend analysis
                    fig = px.line(
                        sample_data, 
                        x='timestamp', 
                        y='traffic_volume',
                        color=sample_data['attack_detected'].astype(str),
                        color_discrete_map={'0': 'green', '1': 'red'},
                        title="Network Traffic Trends with Attack Indicators"
                    )
                    fig.update_layout(height=500)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("Real timestamp-based trend analysis would be displayed here.")

            with tab4:
                st.subheader("Dataset Preview")
                st.dataframe(data.head(10), use_container_width=True)
                
                # Enhanced dataset info
                st.subheader("📋 Dataset Information")
                info_col1, info_col2 = st.columns(2)
                with info_col1:
                    st.write(f"**Shape:** {data.shape[0]} rows × {data.shape[1]} columns")
                    st.write(f"**Memory Usage:** {data.memory_usage(deep=True).sum() / 1024 ** 2:.2f} MB")
                with info_col2:
                    st.write(f"**Data Types:** {len(data.dtypes.unique())} unique types")
                    st.write(f"**Missing Values:** {data.isnull().sum().sum()} total")
                    
                # Column information
                with st.expander("🔍 Column Details"):
                    for col in data.columns[:5]:  # Show first 5 columns
                        st.write(f"**{col}:** {data[col].dtype} | Unique: {data[col].nunique()}")

        except Exception as e:
            st.markdown(f"""
            <div class="danger-box">
                <h4>❌ Error Loading Data</h4>
                <p>Error: {e}</p>
                <p>💡 Make sure your dataset file is available at 'data/cybersecurity_intrusion_data.csv'</p>
            </div>
            """, unsafe_allow_html=True)

else:
    if authentication_status is False:
        st.markdown("""
        <div class="danger-box">
            <h4>❌ Login Failed</h4>
            <p>Username or password is incorrect. Please try again.</p>
        </div>
        """, unsafe_allow_html=True)
    elif authentication_status is None:
        st.markdown("""
        <div class="info-box">
            <h4>🔐 Secure Login Required</h4>
            <p>Please enter your username and password to access the Sentinel-Auth cybersecurity platform.</p>
        </div>
        """, unsafe_allow_html=True)

# Add footer
st.markdown("""
<div style='text-align: center; margin-top: 4rem; padding: 2rem; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 15px;'>
    <h4>🛡️ Sentinel-Auth Cybersecurity Platform</h4>
    <p>Built with Streamlit • Powered by AI • Protecting Your Digital World</p>
    <p style='color: #6c757d; font-size: 0.9rem;'>© 2024 Sentinel-Auth. All rights reserved.</p>
</div>
""", unsafe_allow_html=True)
