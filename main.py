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
from datetime import datetime, timedelta

# --------------------------
# PAGE CONFIGURATION
# --------------------------
st.set_page_config(
    page_title="Sentinel-Auth | AI Threat Detection & Prevention",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
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
        border-bottom: 2px solid #2e86ab;
        padding-bottom: 0.5rem;
        margin-bottom: 1.5rem;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .danger-box {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .info-box {
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .prevention-box {
        background-color: #e8f5e8;
        border: 2px solid #4caf50;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 15px;
        padding: 20px;
        color: white;
        text-align: center;
        margin: 10px 0;
    }
    .tip-card {
        background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%);
        border-radius: 15px;
        padding: 15px;
        color: white;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# --------------------------
# HASHED PASSWORDS & AUTHENTICATION
# --------------------------
hashed_passwords = stauth.Hasher(["admin123", "user123"]).generate()
credentials = {
    "usernames": {
        "admin": {"name": "Administrator", "password": hashed_passwords[0]},
        "bhavya": {"name": "Bhavya", "password": hashed_passwords[1]},
    }
}

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
            ]
        }
        return recommendations.get(threat_type, ["No specific recommendations available."])

# --------------------------
# MAIN APPLICATION
# --------------------------
st.markdown('<div class="main-header">🛡️ Sentinel-Auth - AI Threat Detection & Prevention</div>', unsafe_allow_html=True)

name, authentication_status, username = authenticator.login(fields={"form_name": "Login"}, location="main")

if authentication_status:
    # Sidebar with better styling
    with st.sidebar:
        st.success(f"🎉 Welcome, **{name}**!")
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
        **Sentinel-Auth** is an AI-powered threat detection & prevention system that combines:
        - Real-time URL scanning
        - Proactive threat prevention
        - Wikipedia AI chatbot
        - Cybersecurity analytics
        """)

    # Wikipedia Chatbot Section (keep existing code)
    if "📚 Wikipedia Chatbot" in section:
        # ... (your existing Wikipedia chatbot code remains the same)
        st.markdown('<div class="section-header">🤖 Wikipedia AI Assistant</div>', unsafe_allow_html=True)
        # ... rest of your existing code

    # Security Tools Section (keep existing code)
    elif "🛡️ Security Tools" in section:
        # ... (your existing security tools code remains the same)
        st.markdown('<div class="section-header">🔒 AI Threat Detection Scanner</div>', unsafe_allow_html=True)
        # ... rest of your existing code

    # NEW: THREAT PREVENTION SECTION
    elif "🛡️ Threat Prevention" in section:
        st.markdown('<div class="section-header">🛡️ AI-Powered Threat Prevention</div>', unsafe_allow_html=True)
        
        # Prevention Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown("""
            <div class="metric-card">
                <h3>🔐 Password</h3>
                <h2>Strength Analyzer</h2>
                <p>AI-Powered Security</p>
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
                <h3>💡 Security</h3>
                <h2>Recommendations</h2>
                <p>AI-Generated Tips</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="metric-card">
                <h3>🛡️ Proactive</h3>
                <h2>Protection</h2>
                <p>Prevent Attacks</p>
            </div>
            """, unsafe_allow_html=True)

        # Prevention Tools in Tabs
        prev_tab1, prev_tab2, prev_tab3 = st.tabs(["🔐 Password Security", "🎣 Phishing Detection", "💡 Security Recommendations"])
        
        with prev_tab1:
            st.subheader("AI Password Strength Analyzer")
            
            col1, col2 = st.columns([2, 1])
            with col1:
                password = st.text_input("Enter password to analyze:", type="password", placeholder="Type your password here...")
                analyze_btn = st.button("🔍 Analyze Password", use_container_width=True)
            
            with col2:
                st.write("")
                st.write("")
                generate_btn = st.button("🎲 Generate Secure Password", use_container_width=True)
            
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
            st.subheader("AI Phishing Detection")
            
            email_text = st.text_area(
                "Paste email/text content to analyze:",
                height=150,
                placeholder="Paste the suspicious email or message content here..."
            )
            
            if st.button("🔍 Analyze for Phishing", use_container_width=True):
                if email_text:
                    with st.spinner("🤖 AI analyzing content for phishing indicators..."):
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
        
        with prev_tab3:
            st.subheader("AI Security Recommendations")
            
            threat_type = st.selectbox(
                "Select threat type for recommendations:",
                ["phishing", "malware", "weak_password", "network"]
            )
            
            if st.button("🎯 Get AI Recommendations", use_container_width=True):
                recommendations = ThreatPrevention.get_security_recommendations(threat_type)
                
                st.markdown(f"""
                <div class="prevention-box">
                    <h4>🛡️ AI-Generated Security Recommendations for {threat_type.replace('_', ' ').title()}:</h4>
                """, unsafe_allow_html=True)
                
                for i, rec in enumerate(recommendations, 1):
                    st.write(f"{i}. {rec}")
                
                st.markdown("</div>", unsafe_allow_html=True)
                
                # Additional tips
                st.markdown("""
                <div class="info-box">
                    <h4>💡 Proactive Security Measures:</h4>
                    <ul>
                        <li>Regular security awareness training</li>
                        <li>Implement multi-layered security defense</li>
                        <li>Regular security audits and updates</li>
                        <li>Backup critical data regularly</li>
                        <li>Monitor systems for unusual activity</li>
                    </ul>
                </div>
                """, unsafe_allow_html=True)

    # Data Visualization Section (keep existing code)
    elif "📊 Data Visualization" in section:
        # ... (your existing data visualization code remains the same)
        st.markdown('<div class="section-header">📈 Cybersecurity Analytics Dashboard</div>', unsafe_allow_html=True)
        # ... rest of your existing code

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
            <p>Please enter your username and password to access the Sentinel-Auth system.</p>
        </div>
        """, unsafe_allow_html=True)
