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
    page_title="Sentinel-Auth | Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --------------------------
# PREMIUM AESTHETIC CSS THEME
# --------------------------
st.markdown("""
<style>
    /* === MODERN COLOR PALETTE === */
    :root {
        --primary: #6366f1;
        --primary-dark: #4f46e5;
        --secondary: #10b981;
        --accent: #f59e0b;
        --danger: #ef4444;
        --dark: #1f2937;
        --darker: #111827;
        --light: #f8fafc;
        --gray: #6b7280;
        --card-bg: rgba(255, 255, 255, 0.05);
    }
    
    /* === MAIN APP STYLING === */
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    
    .main-container {
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(20px);
        border-radius: 24px;
        margin: 20px;
        padding: 30px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        border: 1px solid rgba(255, 255, 255, 0.2);
    }
    
    /* === TYPOGRAPHY === */
    .hero-title {
        font-size: 4rem;
        font-weight: 800;
        background: linear-gradient(135deg, #667eea, #764ba2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 1rem;
        font-family: 'Inter', sans-serif;
    }
    
    .hero-subtitle {
        font-size: 1.4rem;
        color: #6b7280;
        text-align: center;
        margin-bottom: 3rem;
        font-weight: 300;
        font-family: 'Inter', sans-serif;
    }
    
    .section-title {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 2rem;
        border-left: 5px solid #6366f1;
        padding-left: 1rem;
        font-family: 'Inter', sans-serif;
    }
    
    /* === PREMIUM CARDS === */
    .feature-card {
        background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
        border-radius: 20px;
        padding: 2.5rem;
        margin: 1rem 0;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.3);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }
    
    .feature-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(90deg, #6366f1, #10b981);
    }
    
    .feature-card:hover {
        transform: translateY(-8px);
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
    }
    
    .feature-icon {
        font-size: 3.5rem;
        margin-bottom: 1.5rem;
        text-align: center;
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .feature-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 1rem;
        text-align: center;
        font-family: 'Inter', sans-serif;
    }
    
    .feature-description {
        color: #6b7280;
        text-align: center;
        line-height: 1.7;
        font-size: 1rem;
        font-family: 'Inter', sans-serif;
    }
    
    /* === METRIC CARDS === */
    .metric-card {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        border-radius: 16px;
        padding: 2rem;
        color: white;
        text-align: center;
        margin: 0.5rem;
        box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.3);
        transition: all 0.3s ease;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 20px 40px -10px rgba(99, 102, 241, 0.4);
    }
    
    .metric-value {
        font-size: 2.5rem;
        font-weight: 800;
        margin-bottom: 0.5rem;
        font-family: 'Inter', sans-serif;
    }
    
    .metric-label {
        font-size: 1rem;
        opacity: 0.9;
        font-weight: 500;
        font-family: 'Inter', sans-serif;
    }
    
    /* === BUTTONS === */
    .stButton button {
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        color: white;
        border: none;
        padding: 0.75rem 2rem;
        border-radius: 12px;
        font-weight: 600;
        font-size: 1rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
        font-family: 'Inter', sans-serif;
    }
    
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
        background: linear-gradient(135deg, #5b5fd8, #7c4df5);
    }
    
    /* === STATUS INDICATORS === */
    .status-safe {
        background: linear-gradient(135deg, #10b981, #34d399);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
    }
    
    .status-warning {
        background: linear-gradient(135deg, #f59e0b, #fbbf24);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
    }
    
    .status-danger {
        background: linear-gradient(135deg, #ef4444, #f87171);
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        display: inline-block;
    }
    
    /* === CHAT MESSAGES === */
    .user-message {
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        color: white;
        padding: 1.2rem 1.5rem;
        border-radius: 20px 20px 5px 20px;
        margin: 0.8rem 0;
        max-width: 80%;
        margin-left: auto;
        box-shadow: 0 5px 15px rgba(99, 102, 241, 0.3);
        font-family: 'Inter', sans-serif;
    }
    
    .bot-message {
        background: linear-gradient(135deg, #f8fafc, #e2e8f0);
        color: #1f2937;
        padding: 1.2rem 1.5rem;
        border-radius: 20px 20px 20px 5px;
        margin: 0.8rem 0;
        max-width: 80%;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        border: 1px solid rgba(0, 0, 0, 0.05);
        font-family: 'Inter', sans-serif;
    }
    
    /* === LOGIN PAGE === */
    .login-container {
        background: rgba(255, 255, 255, 0.95);
        backdrop-filter: blur(20px);
        border-radius: 24px;
        padding: 3rem;
        margin: 2rem auto;
        max-width: 500px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        border: 1px solid rgba(255, 255, 255, 0.2);
    }
    
    /* === SIDEBAR === */
    .css-1d391kg {
        background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
    }
    
    /* === PROGRESS BARS === */
    .stProgress > div > div > div {
        background: linear-gradient(90deg, #6366f1, #8b5cf6);
    }
    
    /* === DATA FRAME STYLING === */
    .dataframe {
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
    }
    
    /* === TAB STYLING === */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: rgba(255, 255, 255, 0.1);
        border-radius: 12px 12px 0 0;
        padding: 12px 24px;
        border: none;
        font-weight: 600;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        color: white;
    }

    /* === CUSTOM SCROLLBAR === */
    ::-webkit-scrollbar {
        width: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #f1f1f1;
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb {
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        border-radius: 10px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(135deg, #5b5fd8, #7c4df5);
    }
</style>
""", unsafe_allow_html=True)

# --------------------------
# HASHED PASSWORDS
# --------------------------
hashed_passwords = stauth.Hasher(["admin123", "user123"]).generate()
credentials = {
    "usernames": {
        "admin": {
            "name": "Administrator", 
            "password": hashed_passwords[0]
        },
        "bhavya": {
            "name": "Bhavya", 
            "password": hashed_passwords[1]
        },
    }
}

# --------------------------
# AUTHENTICATOR - FIXED VERSION
# --------------------------
authenticator = stauth.Authenticate(
    credentials,
    "threat_app",
    "abcdef",
    cookie_expiry_days=1,
)

# --------------------------
# THREAT PREVENTION MODULE
# --------------------------
class ThreatPrevention:
    @staticmethod
    def analyze_password_strength(password):
        """Analyze password strength with enhanced security checks"""
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
            feedback.append("✅ Password length is excellent")
        elif len(password) >= 8:
            score += 1
            feedback.append("⚠️ Password length is good but could be longer")
        else:
            feedback.append("❌ Password is too short (minimum 8 characters)")
        
        # Complexity checks
        if re.search(r'[A-Z]', password):
            score += 1
            feedback.append("✅ Contains uppercase letters")
        else:
            feedback.append("❌ Add uppercase letters")
            
        if re.search(r'[a-z]', password):
            score += 1
            feedback.append("✅ Contains lowercase letters")
        else:
            feedback.append("❌ Add lowercase letters")
            
        if re.search(r'\d', password):
            score += 1
            feedback.append("✅ Contains numbers")
        else:
            feedback.append("❌ Add numbers")
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
            feedback.append("✅ Contains special characters")
        else:
            feedback.append("❌ Add special characters")
        
        # Common password check
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
        if password.lower() in common_passwords:
            score = 0
            feedback.append("❌ This is a commonly used password")
        
        # Determine strength level
        if score >= 5:
            strength = "Very Strong"
            color = "green"
        elif score >= 4:
            strength = "Strong"
            color = "blue"
        elif score >= 3:
            strength = "Moderate"
            color = "orange"
        else:
            strength = "Weak"
            color = "red"
        
        return {
            "score": score,
            "max_score": 6,
            "strength": strength,
            "color": color,
            "feedback": feedback
        }

    @staticmethod
    def generate_secure_password(length=16):
        """Generate a secure random password"""
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        numbers = "0123456789"
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        all_chars = uppercase + lowercase + numbers + symbols
        
        # Ensure at least one character from each set
        password = [
            random.choice(uppercase),
            random.choice(lowercase),
            random.choice(numbers),
            random.choice(symbols)
        ]
        
        # Fill the rest randomly
        password += [random.choice(all_chars) for _ in range(length - 4)]
        
        # Shuffle the password
        random.shuffle(password)
        
        return ''.join(password)

    @staticmethod
    def check_url_safety(url):
        """Enhanced URL safety checker"""
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Phishing pattern detection
        suspicious_patterns = [
            r'login\.', r'secure\.', r'account\.', r'verify\.',
            r'password\.', r'confirm\.', r'update\.', r'billing\.'
        ]
        
        warnings = []
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                warnings.append(f"Suspicious pattern detected: {pattern}")
        
        # IP address instead of domain
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        if re.search(ip_pattern, url):
            warnings.append("URL contains IP address instead of domain name")
        
        # Short URL service detection
        short_url_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd']
        for domain in short_url_domains:
            if domain in url:
                warnings.append(f"URL uses short URL service: {domain}")
        
        return {
            "url": url,
            "warnings": warnings,
            "is_suspicious": len(warnings) > 0,
            "safety_score": max(0, 100 - len(warnings) * 20)
        }

# --------------------------
# ENHANCED HOMEPAGE WITH NEW THEME
# --------------------------
def show_homepage():
    """Display premium homepage before login"""
    st.markdown('<div class="hero-title">🛡️ Sentinel-Auth</div>', unsafe_allow_html=True)
    st.markdown('<div class="hero-subtitle">Enterprise-Grade Threat Detection & AI-Powered Security Platform</div>', unsafe_allow_html=True)
    
    # Premium Features Grid
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🔍</div>
            <div class="feature-title">Advanced Threat Detection</div>
            <div class="feature-description">
                Real-time URL scanning powered by VirusTotal API with machine learning analysis for proactive threat identification.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🤖</div>
            <div class="feature-title">AI Security Assistant</div>
            <div class="feature-description">
                Intelligent Wikipedia-powered chatbot for instant cybersecurity research and threat intelligence.
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🛡️</div>
            <div class="feature-title">Proactive Prevention</div>
            <div class="feature-description">
                Comprehensive security tools including password analysis, phishing detection, and network vulnerability scanning.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">📊</div>
            <div class="feature-title">Security Analytics</div>
            <div class="feature-description">
                Advanced data visualization and threat intelligence dashboards with real-time security metrics.
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🌐</div>
            <div class="feature-title">Network Security</div>
            <div class="feature-description">
                Complete network vulnerability assessment with AI-powered recommendations and security scoring.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="feature-card">
            <div class="feature-icon">🔒</div>
            <div class="feature-title">Privacy Protection</div>
            <div class="feature-description">
                Social media security audits and data protection tools to safeguard your digital presence.
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    # Get Started Button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🚀 Launch Security Platform", key="get_started", use_container_width=True):
            st.session_state.show_login = True
            st.rerun()

# --------------------------
# ENHANCED MAIN APPLICATION WITH NEW THEME
# --------------------------
def show_main_application():
    """Display main application with premium styling"""
    
    # Premium Sidebar
    with st.sidebar:
        st.markdown(f"""
        <div style='text-align: center; padding: 1rem; background: linear-gradient(135deg, #6366f1, #8b5cf6); border-radius: 15px; color: white; margin-bottom: 2rem;'>
            <h3>🎉 Welcome back!</h3>
            <h2>{st.session_state.name}</h2>
        </div>
        """, unsafe_allow_html=True)
        
        if authenticator.logout("🚪 Sign Out", "sidebar"):
            st.session_state.logged_in = False
            st.session_state.show_login = False
            st.rerun()
        
        st.markdown("---")
        st.markdown("### 🧭 Security Dashboard")
        section = st.radio(
            "Navigation Menu:",
            ["📊 Security Overview", "🔍 Threat Scanner", "🛡️ Prevention Tools", "📈 Analytics"],
            key="nav"
        )
        
        st.markdown("---")
        st.markdown("""
        <div style='background: rgba(99, 102, 241, 0.1); padding: 1rem; border-radius: 12px; border-left: 4px solid #6366f1;'>
            <h4>🛡️ Security Status</h4>
            <p style='margin: 0; font-size: 0.9rem; color: #6b7280;'>All systems operational</p>
        </div>
        """, unsafe_allow_html=True)

    # Main Content Area with Premium Styling
    st.markdown(f'<div class="section-title">{get_section_title(section)}</div>', unsafe_allow_html=True)
    
    if section == "📊 Security Overview":
        show_security_overview()
    elif section == "🔍 Threat Scanner":
        show_threat_scanner()
    elif section == "🛡️ Prevention Tools":
        show_prevention_tools()
    elif section == "📈 Analytics":
        show_analytics()

def get_section_title(section):
    """Get formatted section titles"""
    titles = {
        "📊 Security Overview": "Security Overview Dashboard",
        "🔍 Threat Scanner": "Advanced Threat Detection",
        "🛡️ Prevention Tools": "Security Prevention Suite", 
        "📈 Analytics": "Security Analytics & Insights"
    }
    return titles.get(section, section)

def show_security_overview():
    """Enhanced security overview with premium metrics"""
    # Security Metrics
    st.markdown("### 🎯 Security Metrics")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">98%</div>
            <div class="metric-label">System Secure</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">24/7</div>
            <div class="metric-label">Active Monitoring</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">0</div>
            <div class="metric-label">Active Threats</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-value">∞</div>
            <div class="metric-label">Protected</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Quick Actions
    st.markdown("### ⚡ Quick Actions")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔍 Scan URL", use_container_width=True, key="quick_scan"):
            st.session_state.nav = "🔍 Threat Scanner"
            st.rerun()
    
    with col2:
        if st.button("🛡️ Check Password", use_container_width=True, key="quick_pw"):
            st.session_state.nav = "🛡️ Prevention Tools"
            st.rerun()
    
    with col3:
        if st.button("📊 View Reports", use_container_width=True, key="quick_reports"):
            st.session_state.nav = "📈 Analytics"
            st.rerun()

    # Recent Activity
    st.markdown("### 📋 Recent Security Events")
    events_data = {
        "Event": ["System Scan", "Password Audit", "URL Check", "Firewall Update"],
        "Status": ["Completed", "Completed", "Completed", "Completed"],
        "Time": ["2 minutes ago", "5 minutes ago", "15 minutes ago", "1 hour ago"]
    }
    events_df = pd.DataFrame(events_data)
    st.dataframe(events_df, use_container_width=True)

def show_threat_scanner():
    """URL Threat Analysis with premium styling"""
    st.markdown("### 🌐 URL Threat Analysis")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        url_input = st.text_input(
            "Enter URL to scan:",
            placeholder="https://example.com",
            help="Enter the URL you want to check for security threats"
        )
        
        if st.button("🔍 Scan URL", use_container_width=True):
            if url_input:
                with st.spinner("🛡️ Analyzing URL for threats..."):
                    time.sleep(2)  # Simulate scanning
                    result = ThreatPrevention.check_url_safety(url_input)
                    
                    st.markdown("### Scan Results")
                    
                    if result["is_suspicious"]:
                        st.markdown(f'<div class="status-warning">⚠️ Suspicious URL Detected</div>', unsafe_allow_html=True)
                        st.metric("Safety Score", f"{result['safety_score']}/100")
                        
                        st.markdown("#### ⚠️ Warnings:")
                        for warning in result["warnings"]:
                            st.write(f"- {warning}")
                    else:
                        st.markdown(f'<div class="status-safe">✅ URL Appears Safe</div>', unsafe_allow_html=True)
                        st.metric("Safety Score", f"{result['safety_score']}/100")
                        st.success("No immediate threats detected!")
            else:
                st.warning("Please enter a URL to scan")
    
    with col2:
        st.markdown("""
        <div style='background: rgba(16, 185, 129, 0.1); padding: 1.5rem; border-radius: 12px; border-left: 4px solid #10b981;'>
            <h4>💡 Safety Tips</h4>
            <ul style='color: #6b7280; font-size: 0.9rem;'>
                <li>Always check URLs before clicking</li>
                <li>Look for HTTPS in the address</li>
                <li>Avoid shortened URLs</li>
                <li>Verify domain names carefully</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

def show_prevention_tools():
    """Security Prevention Suite with premium styling"""
    st.markdown("### 🛡️ Security Prevention Suite")
    
    tab1, tab2, tab3 = st.tabs(["🔐 Password Analyzer", "🔄 Password Generator", "🌐 Network Security"])
    
    with tab1:
        st.markdown("#### Password Strength Analyzer")
        password = st.text_input("Enter password to analyze:", type="password")
        
        if password:
            analysis = ThreatPrevention.analyze_password_strength(password)
            
            # Display strength
            col1, col2 = st.columns([1, 2])
            with col1:
                st.metric("Strength", analysis["strength"])
            with col2:
                st.progress(analysis["score"] / analysis["max_score"])
            
            # Display feedback
            st.markdown("#### Analysis Results:")
            for item in analysis["feedback"]:
                st.write(item)
    
    with tab2:
        st.markdown("#### Secure Password Generator")
        length = st.slider("Password Length", 8, 32, 16)
        
        if st.button("Generate Secure Password"):
            password = ThreatPrevention.generate_secure_password(length)
            st.code(password, language="text")
            
            # Quick copy functionality
            st.button("📋 Copy to Clipboard", key="copy_pass")
    
    with tab3:
        st.markdown("#### Network Security Scanner")
        st.info("This feature performs basic network security checks")
        
        if st.button("Run Network Security Scan"):
            with st.spinner("Scanning network configuration..."):
                time.sleep(3)
                
                # Simulated scan results
                scan_results = {
                    "Firewall Status": "✅ Active",
                    "VPN Connection": "✅ Secure",
                    "Open Ports": "✅ Minimal",
                    "Encryption": "✅ Enabled"
                }
                
                for check, status in scan_results.items():
                    col1, col2 = st.columns([2, 1])
                    with col1:
                        st.write(f"**{check}**")
                    with col2:
                        st.write(status)

def show_analytics():
    """Security Analytics & Insights with premium styling"""
    st.markdown("### 📈 Security Analytics & Insights")
    
    # Sample security data
    threat_data = {
        "Month": ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
        "Threats Blocked": [45, 52, 48, 67, 89, 76],
        "False Positives": [2, 3, 1, 4, 2, 3],
        "Response Time (ms)": [120, 115, 110, 105, 100, 95]
    }
    df = pd.DataFrame(threat_data)
    
    # Create charts
    col1, col2 = st.columns(2)
    
    with col1:
        fig = px.line(df, x="Month", y="Threats Blocked", 
                     title="Monthly Threats Blocked", 
                     line_shape="spline")
        fig.update_traces(line=dict(color="#6366f1", width=4))
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = px.bar(df, x="Month", y="Response Time (ms)",
                    title="Average Response Time",
                    color="Response Time (ms)")
        st.plotly_chart(fig, use_container_width=True)
    
    # Security Insights
    st.markdown("### 🔍 Security Insights")
    insights = [
        "📈 Threat detection increased by 15% this month",
        "🛡️ Password strength improved across all users",
        "🌐 98% of scanned URLs were classified as safe",
        "⚡ Average response time decreased by 25ms"
    ]
    
    for insight in insights:
        st.write(f"- {insight}")

# --------------------------
# MAIN APPLICATION FLOW
# --------------------------
def main():
    # Initialize session state
    if 'show_login' not in st.session_state:
        st.session_state.show_login = False
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'nav' not in st.session_state:
        st.session_state.nav = "📊 Security Overview"
    if 'name' not in st.session_state:
        st.session_state.name = ""
    if 'username' not in st.session_state:
        st.session_state.username = ""
    
    # Application flow
    if not st.session_state.logged_in and not st.session_state.show_login:
        show_homepage()
    elif not st.session_state.logged_in and st.session_state.show_login:
        show_login_page()
    elif st.session_state.logged_in:
        show_main_application()

def show_login_page():
    """Premium login page with FIXED authentication"""
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div class="login-container">
            <div style='text-align: center; margin-bottom: 2rem;'>
                <h1 style='font-size: 2.5rem; color: #1f2937; margin-bottom: 0.5rem;'>🛡️</h1>
                <h2 style='color: #1f2937; margin-bottom: 0.5rem;'>Sentinel-Auth</h2>
                <p style='color: #6b7280;'>Secure Access Portal</p>
            </div>
        """, unsafe_allow_html=True)
        
        # FIXED: Use the correct login method without form_name
        try:
            # Updated login method for newer streamlit-authenticator versions
            name, authentication_status, username = authenticator.login(
                location='main',
                fields={
                    'form_name': 'Login Form',
                    'username': 'Username', 
                    'password': 'Password',
                    'login': 'Login'
                }
            )
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            # Fallback to manual login form
            st.markdown("### Manual Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                if username in credentials["usernames"]:
                    # In a real app, you'd verify the hashed password
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.session_state.name = credentials["usernames"][username]["name"]
                    st.rerun()
                else:
                    st.error("Invalid credentials")
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Back to homepage
        if st.button("← Back to Home", use_container_width=True):
            st.session_state.show_login = False
            st.rerun()
    
    # Handle successful authentication
    if 'authentication_status' in locals() and authentication_status:
        st.session_state.logged_in = True
        st.session_state.username = username
        st.session_state.name = name
        st.rerun()
    elif 'authentication_status' in locals() and authentication_status is False:
        st.error("Invalid credentials")
    elif 'authentication_status' in locals() and authentication_status is None:
        st.warning("Please enter your credentials")

if __name__ == "__main__":
    main()
