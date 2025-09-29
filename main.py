import streamlit as st
import wikipedia
import streamlit_authenticator as stauth
import requests
import pandas as pd
import base64, time
import plotly.express as px
import plotly.graph_objects as go

# --------------------------
# PAGE CONFIGURATION
# --------------------------
st.set_page_config(
    page_title="Sentinel-Auth | AI Threat Detection",
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
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 15px;
        padding: 20px;
        color: white;
        text-align: center;
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
# LOGIN PAGE TITLE
# --------------------------
st.markdown('<div class="main-header">🛡️ Sentinel-Auth</div>', unsafe_allow_html=True)

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
            ["📚 Wikipedia Chatbot", "🛡️ Security Tools", "📊 Data Visualization"],
            key="nav"
        )
        
        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.info("""
        **Sentinel-Auth** is an AI-powered threat detection system that combines:
        - Real-time URL scanning
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
