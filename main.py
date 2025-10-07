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
# REST OF YOUR CODE REMAINS EXACTLY THE SAME
# (Hashed passwords, authenticator, ThreatPrevention class, etc.)
# --------------------------

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
# (Keep all your existing ThreatPrevention class code exactly as it was)
# --------------------------
class ThreatPrevention:
    # ... [ALL YOUR EXISTING ThreatPrevention METHODS EXACTLY AS THEY WERE]
    @staticmethod
    def analyze_password_strength(password):
        # ... your existing code
        pass
    
    @staticmethod
    def generate_secure_password(length=12):
        # ... your existing code
        pass
    
    # ... all other methods

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
            st.experimental_rerun()

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
            st.experimental_rerun()
        
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
            st.experimental_rerun()
    
    with col2:
        if st.button("🛡️ Check Password", use_container_width=True, key="quick_pw"):
            st.session_state.nav = "🛡️ Prevention Tools"
            st.experimental_rerun()
    
    with col3:
        if st.button("📊 View Reports", use_container_width=True, key="quick_reports"):
            st.session_state.nav = "📈 Analytics"
            st.experimental_rerun()

# ... [KEEP ALL YOUR EXISTING show_threat_scanner(), show_prevention_tools(), show_analytics() FUNCTIONS]
# Just replace the section headers to use the new CSS classes

def show_threat_scanner():
    """Your existing URL scanner with premium styling"""
    st.markdown("### 🌐 URL Threat Analysis")
    
    # Your existing URL scanner code here, but replace:
    # st.success → <div class="status-safe">
    # st.warning → <div class="status-warning"> 
    # st.error → <div class="status-danger">

def show_prevention_tools():
    """Your existing prevention tools with premium styling"""
    st.markdown("### 🛡️ Security Prevention Suite")
    
    # Your existing prevention tools code here
    # Use the new CSS classes for cards and buttons

def show_analytics():
    """Your existing analytics with premium styling"""
    st.markdown("### 📈 Security Intelligence")
    
    # Your existing analytics code here

# --------------------------
# MAIN APPLICATION FLOW (Keep your existing flow)
# --------------------------
def main():
    # Initialize session state
    if 'show_login' not in st.session_state:
        st.session_state.show_login = False
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'nav' not in st.session_state:
        st.session_state.nav = "📊 Security Overview"
    
    # Application flow
    if not st.session_state.logged_in and not st.session_state.show_login:
        show_homepage()
    elif not st.session_state.logged_in and st.session_state.show_login:
        show_login_page()
    elif st.session_state.logged_in:
        show_main_application()

def show_login_page():
    """Premium login page"""
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
        
        # Login form
        try:
            name, authentication_status, username = authenticator.login('Login', 'main')
        except Exception as e:
            st.error(f"Authentication error: {e}")
            name, authentication_status, username = None, False, None
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Back to homepage
        if st.button("← Back to Home", use_container_width=True):
            st.session_state.show_login = False
            st.experimental_rerun()
    
    # Handle login
    if authentication_status:
        st.session_state.logged_in = True
        st.session_state.username = username
        st.session_state.name = name
        st.experimental_rerun()

if __name__ == "__main__":
    main()
