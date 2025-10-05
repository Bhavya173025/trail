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
            ]
        }
        return recommendations.get(threat_type, ["No specific recommendations available."])

# --------------------------
# LOGIN PAGE TITLE
# --------------------------
st.markdown('<div class="main-header">🛡️ Sentinel-Auth - AI Threat Detection & Prevention</div>', unsafe_allow_html=True)

# --------------------------
# LOGIN FORM
# --------------------------
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

    # Wikipedia Chatbot Section
    if "📚 Wikipedia Chatbot" in section:
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
                <div style='background-color: #e3f2fd; padding: 15px; border-radius: 15px; margin: 10px 0; border: 1px solid #bbdefb;'>
                    <strong>👤 You:</strong> {msg['content']}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style='background-color: #f3e5f5; padding: 15px; border-radius: 15px; margin: 10px 0; border: 1px solid #e1bee7;'>
                    <strong>🤖 Choco:</strong> {msg['content']}
                </div>
                """, unsafe_allow_html=True)

    # Security Tools Section
    elif "🛡️ Security Tools" in section:
        st.markdown('<div class="section-header">🔒 AI Threat Detection Scanner</div>', unsafe_allow_html=True)
        
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

    # Data Visualization Section
    elif "📊 Data Visualization" in section:
        st.markdown('<div class="section-header">📈 Cybersecurity Analytics Dashboard</div>', unsafe_allow_html=True)
        
        try:
            data = pd.read_csv('data/cybersecurity_intrusion_data.csv')
            
            # Create columns for metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                total_attacks = data['attack_detected'].sum() if 'attack_detected' in data.columns else 0
                st.metric("🚨 Total Attacks", total_attacks)
            
            with col2:
                total_records = len(data)
                st.metric("📊 Total Records", total_records)
            
            with col3:
                attack_rate = (total_attacks / total_records * 100) if total_records > 0 else 0
                st.metric("📈 Attack Rate", f"{attack_rate:.1f}%")
            
            with col4:
                if 'protocol_type' in data.columns:
                    unique_protocols = data['protocol_type'].nunique()
                    st.metric("🔧 Protocols", unique_protocols)

            # Create tabs for different visualizations
            tab1, tab2, tab3 = st.tabs(["📊 Attack Distribution", "🔧 Protocol Analysis", "📋 Data Preview"])
            
            with tab1:
                st.subheader("Attack vs Non-Attack Distribution")
                if 'attack_detected' in data.columns:
                    attack_counts = data['attack_detected'].value_counts()
                    
                    # Use Plotly for better charts
                    fig = px.pie(
                        values=attack_counts.values, 
                        names=['Non-Attack' if x == 0 else 'Attack' for x in attack_counts.index],
                        color=['Non-Attack' if x == 0 else 'Attack' for x in attack_counts.index],
                        color_discrete_map={'Non-Attack':'green', 'Attack':'red'}
                    )
                    fig.update_traces(textposition='inside', textinfo='percent+label')
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
                        color_continuous_scale='viridis'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("Protocol type data not available in the dataset.")

            with tab3:
                st.subheader("Dataset Preview")
                st.dataframe(data.head(10), use_container_width=True)
                
                # Dataset info
                st.subheader("Dataset Information")
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Shape:** {data.shape}")
                    st.write(f"**Columns:** {len(data.columns)}")
                with col2:
                    st.write(f"**Memory Usage:** {data.memory_usage(deep=True).sum() / 1024 ** 2:.2f} MB")
                    
        except Exception as e:
            st.error(f"❌ Error loading or visualizing data: {e}")
            st.info("💡 Make sure your dataset file is available at 'data/cybersecurity_intrusion_data.csv'")

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
