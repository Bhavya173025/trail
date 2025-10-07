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
# PROFESSIONAL DUAL-MODE CSS THEME
# --------------------------
st.markdown("""
<style>
    /* === PROFESSIONAL COLOR PALETTE === */
    :root {
        --primary: #2563eb;
        --primary-dark: #1d4ed8;
        --primary-light: #3b82f6;
        --secondary: #059669;
        --accent: #d97706;
        --neutral: #6b7280;
        --success: #10b981;
        --warning: #f59e0b;
        --error: #ef4444;
        --surface: #ffffff;
        --surface-dark: #1f2937;
        --text-primary: #111827;
        --text-secondary: #6b7280;
        --border: #e5e7eb;
    }
    
    /* === MAIN APP STYLING === */
    .stApp {
        background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
    }
    
    @media (prefers-color-scheme: dark) {
        .stApp {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        }
    }
    
    .main-container {
        background: var(--surface);
        border-radius: 20px;
        margin: 20px;
        padding: 40px;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.08);
        border: 1px solid var(--border);
        backdrop-filter: blur(10px);
    }
    
    @media (prefers-color-scheme: dark) {
        .main-container {
            background: var(--surface-dark);
            border: 1px solid #374151;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
    }
    
    /* === MODERN TYPOGRAPHY === */
    .hero-title {
        font-size: 4.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, var(--primary), var(--secondary));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 1.5rem;
        font-family: 'Inter', 'SF Pro Display', system-ui, sans-serif;
        letter-spacing: -0.02em;
        line-height: 1.1;
    }
    
    .hero-subtitle {
        font-size: 1.5rem;
        color: var(--text-secondary);
        text-align: center;
        margin-bottom: 4rem;
        font-weight: 400;
        font-family: 'Inter', system-ui, sans-serif;
        line-height: 1.6;
        max-width: 800px;
        margin-left: auto;
        margin-right: auto;
    }
    
    .section-title {
        font-size: 2.5rem;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 2.5rem;
        font-family: 'Inter', system-ui, sans-serif;
        text-align: center;
        position: relative;
    }
    
    .section-title::after {
        content: '';
        position: absolute;
        bottom: -10px;
        left: 50%;
        transform: translateX(-50%);
        width: 80px;
        height: 4px;
        background: linear-gradient(90deg, var(--primary), var(--secondary));
        border-radius: 2px;
    }
    
    @media (prefers-color-scheme: dark) {
        .section-title {
            color: #f9fafb;
        }
    }
    
    /* === PREMIUM FEATURE CARDS === */
    .feature-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
        gap: 2rem;
        margin: 3rem 0;
    }
    
    .feature-card {
        background: var(--surface);
        border-radius: 20px;
        padding: 2.5rem;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
        border: 1px solid var(--border);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
        height: 100%;
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
    }
    
    .feature-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(90deg, var(--primary), var(--secondary));
    }
    
    .feature-card:hover {
        transform: translateY(-8px);
        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
        border-color: var(--primary-light);
    }
    
    @media (prefers-color-scheme: dark) {
        .feature-card {
            background: #1f2937;
            border: 1px solid #374151;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .feature-card:hover {
            border-color: var(--primary);
        }
    }
    
    .feature-icon {
        font-size: 4rem;
        margin-bottom: 1.5rem;
        background: linear-gradient(135deg, var(--primary), var(--secondary));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        filter: drop-shadow(0 4px 8px rgba(37, 99, 235, 0.2));
    }
    
    .feature-title {
        font-size: 1.5rem;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 1rem;
        font-family: 'Inter', system-ui, sans-serif;
    }
    
    .feature-description {
        color: var(--text-secondary);
        line-height: 1.7;
        font-size: 1.05rem;
        font-family: 'Inter', system-ui, sans-serif;
        flex-grow: 1;
    }
    
    @media (prefers-color-scheme: dark) {
        .feature-title {
            color: #f9fafb;
        }
        
        .feature-description {
            color: #d1d5db;
        }
    }
    
    /* === ENHANCED BUTTONS === */
    .stButton button {
        background: linear-gradient(135deg, var(--primary), var(--primary-dark));
        color: white;
        border: none;
        padding: 1rem 2.5rem;
        border-radius: 12px;
        font-weight: 600;
        font-size: 1.1rem;
        transition: all 0.3s ease;
        box-shadow: 0 8px 20px rgba(37, 99, 235, 0.3);
        font-family: 'Inter', system-ui, sans-serif;
        position: relative;
        overflow: hidden;
    }
    
    .stButton button::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
        transition: left 0.5s;
    }
    
    .stButton button:hover {
        transform: translateY(-3px);
        box-shadow: 0 12px 30px rgba(37, 99, 235, 0.4);
        background: linear-gradient(135deg, var(--primary-light), var(--primary));
    }
    
    .stButton button:hover::before {
        left: 100%;
    }
    
    /* === HERO SECTION === */
    .hero-section {
        text-align: center;
        padding: 4rem 2rem;
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.05) 0%, rgba(5, 150, 105, 0.05) 100%);
        border-radius: 24px;
        margin: 2rem 0;
        border: 1px solid rgba(37, 99, 235, 0.1);
    }
    
    @media (prefers-color-scheme: dark) {
        .hero-section {
            background: linear-gradient(135deg, rgba(37, 99, 235, 0.1) 0%, rgba(5, 150, 105, 0.1) 100%);
            border: 1px solid rgba(37, 99, 235, 0.2);
        }
    }
    
    /* === STATUS BADGES === */
    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.9rem;
        margin: 0.25rem;
    }
    
    .status-premium {
        background: linear-gradient(135deg, var(--primary), var(--secondary));
        color: white;
    }
    
    .status-feature {
        background: rgba(37, 99, 235, 0.1);
        color: var(--primary);
        border: 1px solid rgba(37, 99, 235, 0.2);
    }
    
    @media (prefers-color-scheme: dark) {
        .status-feature {
            background: rgba(37, 99, 235, 0.2);
            color: #60a5fa;
            border: 1px solid rgba(37, 99, 235, 0.3);
        }
    }
    
    /* === RESPONSIVE DESIGN === */
    @media (max-width: 768px) {
        .hero-title {
            font-size: 3rem;
        }
        
        .hero-subtitle {
            font-size: 1.2rem;
        }
        
        .feature-grid {
            grid-template-columns: 1fr;
            gap: 1.5rem;
        }
        
        .feature-card {
            padding: 2rem;
        }
    }
    
    /* === GLOW EFFECTS === */
    .glow-card {
        position: relative;
    }
    
    .glow-card::after {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        border-radius: 20px;
        padding: 2px;
        background: linear-gradient(135deg, var(--primary), var(--secondary));
        mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
        -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
        -webkit-mask-composite: xor;
        mask-composite: exclude;
        opacity: 0;
        transition: opacity 0.3s ease;
    }
    
    .feature-card:hover .glow-card::after {
        opacity: 1;
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
# AUTHENTICATOR
# --------------------------
authenticator = stauth.Authenticate(
    credentials,
    "threat_app",
    "abcdef",
    cookie_expiry_days=1,
)

# --------------------------
# ENHANCED PROFESSIONAL HOMEPAGE
# --------------------------
def show_homepage():
    """Display premium professional homepage before login"""
    
    # Hero Section
    st.markdown("""
        <div class="hero-section">
            <div class="hero-title">Enterprise Security Intelligence</div>
            <div class="hero-subtitle">
                Advanced threat detection meets intelligent prevention. 
                Protect your digital assets with AI-powered security analytics, 
                real-time monitoring, and proactive defense mechanisms.
            </div>
        </div>
    """, unsafe_allow_html=True)
    
    # Trust Badges
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="status-badge status-premium">🔒 Enterprise Grade</div>', unsafe_allow_html=True)
    with col2:
        st.markdown('<div class="status-badge status-premium">🤖 AI Powered</div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="status-badge status-premium">🌐 Real-Time</div>', unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="status-badge status-premium">⚡ Lightning Fast</div>', unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Premium Features Grid
    st.markdown('<div class="section-title">Comprehensive Security Suite</div>', unsafe_allow_html=True)
    
    # Feature Grid
    features = [
        {
            "icon": "🛡️",
            "title": "Advanced Threat Protection",
            "description": "Multi-layered defense system with real-time threat intelligence and behavioral analysis to detect and neutralize sophisticated cyber attacks.",
            "badges": ["Real-Time", "AI-Powered", "Multi-Layer"]
        },
        {
            "icon": "🔍",
            "title": "Intelligent Vulnerability Scanner",
            "description": "Comprehensive security assessment with automated vulnerability detection and prioritized remediation recommendations.",
            "badges": ["Automated", "Comprehensive", "Smart Prioritization"]
        },
        {
            "icon": "📊",
            "title": "Security Analytics Dashboard",
            "description": "Advanced data visualization and threat intelligence with real-time security metrics and predictive analytics.",
            "badges": ["Real-Time", "Predictive", "Interactive"]
        },
        {
            "icon": "🤖",
            "title": "AI Security Assistant",
            "description": "Intelligent cybersecurity research and threat intelligence powered by advanced machine learning algorithms.",
            "badges": ["24/7", "Intelligent", "Proactive"]
        },
        {
            "icon": "🌐",
            "title": "Network Security Monitor",
            "description": "Complete network vulnerability assessment with continuous monitoring and instant threat detection capabilities.",
            "badges": ["Continuous", "Comprehensive", "Instant Alerts"]
        },
        {
            "icon": "🔐",
            "title": "Identity & Access Management",
            "description": "Advanced authentication protocols and access control systems with zero-trust architecture implementation.",
            "badges": ["Zero-Trust", "Advanced Auth", "Access Control"]
        }
    ]
    
    # Create feature grid
    cols = st.columns(3)
    for idx, feature in enumerate(features):
        with cols[idx % 3]:
            with st.container():
                st.markdown(f"""
                    <div class="feature-card">
                        <div class="feature-icon">{feature['icon']}</div>
                        <div class="feature-title">{feature['title']}</div>
                        <div class="feature-description">{feature['description']}</div>
                        <div style="margin-top: 1rem;">
                            {"".join([f'<span class="status-badge status-feature">{badge}</span>' for badge in feature["badges"]])}
                        </div>
                    </div>
                """, unsafe_allow_html=True)
    
    # CTA Section
    st.markdown("""
        <div style="text-align: center; margin: 4rem 0;">
            <h2 style="color: var(--text-primary); margin-bottom: 1rem; font-family: 'Inter', sans-serif;">
                Ready to Secure Your Digital Environment?
            </h2>
            <p style="color: var(--text-secondary); font-size: 1.1rem; margin-bottom: 2rem;">
                Join thousands of enterprises trusting Sentinel-Auth for their cybersecurity needs
            </p>
        </div>
    """, unsafe_allow_html=True)
    
    # Get Started Button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🚀 Launch Security Platform", key="get_started", use_container_width=True):
            st.session_state.show_login = True
            st.rerun()

# --------------------------
# REST OF YOUR APPLICATION CODE REMAINS EXACTLY THE SAME
# (Authentication, ThreatPrevention class, main app functions)
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

def show_login_page():
    """Professional login page"""
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div style='background: var(--surface); border-radius: 20px; padding: 3rem; box-shadow: 0 20px 40px rgba(0,0,0,0.1); border: 1px solid var(--border);'>
            <div style='text-align: center; margin-bottom: 2rem;'>
                <h1 style='font-size: 2.5rem; color: var(--text-primary); margin-bottom: 0.5rem;'>🛡️</h1>
                <h2 style='color: var(--text-primary); margin-bottom: 0.5rem;'>Sentinel-Auth</h2>
                <p style='color: var(--text-secondary);'>Secure Access Portal</p>
            </div>
        """, unsafe_allow_html=True)
        
        # Login form
        try:
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
            st.markdown("### Manual Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                if username in credentials["usernames"]:
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
    
    # Handle authentication
    if 'authentication_status' in locals() and authentication_status:
        st.session_state.logged_in = True
        st.session_state.username = username
        st.session_state.name = name
        st.rerun()

def main():
    # Initialize session state
    if 'show_login' not in st.session_state:
        st.session_state.show_login = False
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
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
        st.success(f"Welcome {st.session_state.name}!")  # Placeholder for main app

if __name__ == "__main__":
    main()
