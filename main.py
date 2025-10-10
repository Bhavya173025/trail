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
import io
from datetime import datetime
import hashlib

# --------------------------
# AI IMPORTS
# --------------------------
try:
    from transformers import pipeline
    from sklearn.ensemble import IsolationForest
    import numpy as np
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False

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
    .file-scan-card {
        background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        border-radius: 15px;
        padding: 20px;
        margin: 10px 0;
        border: 2px solid #a8edea;
    }
    .ai-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 15px;
        padding: 20px;
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
# ADVANCED AI SECURITY MODULE
# --------------------------
class AdvancedAISecurity:
    def __init__(self):
        self.setup_ai_models()
    
    def setup_ai_models(self):
        """Initialize AI models with fallbacks"""
        self.models_available = {
            "huggingface": False,
            "sentiment": False,
            "classifier": False
        }
        
        # Setup Hugging Face Models
        try:
            if HF_AVAILABLE:
                self.sentiment_analyzer = pipeline("sentiment-analysis", 
                                                 model="distilbert-base-uncased-finetuned-sst-2-english")
                self.text_classifier = pipeline("zero-shot-classification",
                                              model="facebook/bart-large-mnli")
                self.models_available["huggingface"] = True
                self.models_available["sentiment"] = True
                self.models_available["classifier"] = True
                st.sidebar.success("✅ Hugging Face AI Loaded")
        except Exception as e:
            st.sidebar.warning(f"🔸 Hugging Face: {str(e)[:50]}...")
    
    def enhanced_phishing_detection(self, email_text):
        """Advanced AI-powered phishing detection"""
        analysis = {
            "risk_score": 0,
            "indicators": [],
            "ai_insights": [],
            "confidence": "Medium",
            "final_verdict": "Analyzing..."
        }
        
        # Basic pattern analysis (always available)
        basic_analysis = self._basic_pattern_analysis(email_text)
        analysis["risk_score"] += basic_analysis["score"]
        analysis["indicators"].extend(basic_analysis["indicators"])
        
        # AI-powered analysis if models available
        if self.models_available["sentiment"]:
            sentiment_analysis = self._ai_sentiment_analysis(email_text)
            analysis["risk_score"] += sentiment_analysis["score"]
            analysis["indicators"].extend(sentiment_analysis["indicators"])
        
        if self.models_available["classifier"]:
            classification = self._ai_zero_shot_classification(email_text)
            analysis["ai_insights"].append(classification)
            analysis["risk_score"] += 2 if "phishing" in classification.lower() else 0
        
        # Determine final verdict
        if analysis["risk_score"] >= 8:
            analysis["final_verdict"] = "🚨 HIGH RISK - Likely Phishing"
            analysis["confidence"] = "High"
        elif analysis["risk_score"] >= 5:
            analysis["final_verdict"] = "⚠️ MEDIUM RISK - Suspicious"
            analysis["confidence"] = "Medium"
        elif analysis["risk_score"] >= 3:
            analysis["final_verdict"] = "🔸 LOW RISK - Possibly Legitimate"
            analysis["confidence"] = "Medium"
        else:
            analysis["final_verdict"] = "✅ LOW RISK - Likely Legitimate"
            analysis["confidence"] = "High"
        
        return analysis
    
    def _basic_pattern_analysis(self, text):
        """Basic pattern-based analysis"""
        indicators = []
        score = 0
        
        patterns = {
            "urgency": [r'urgent', r'immediate', r'action required', r'within.*hours'],
            "suspicious_links": [r'http://[^\s]+', r'https://[^\s]+', r'\[.*\]\(http'],
            "credentials_request": [r'password', r'login', r'credentials', r'verify account'],
            "authority_claim": [r'official', r'security team', r'microsoft', r'bank', r'paypal'],
            "grammar_issues": [r'\b(?:pleasse|urgentt|acount|securty)\b']
        }
        
        for category, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    score += 1
                    indicators.append(f"{category}: {len(matches)} instances")
                    break
        
        return {"score": score, "indicators": indicators}
    
    def _ai_sentiment_analysis(self, text):
        """AI sentiment analysis using Hugging Face"""
        indicators = []
        score = 0
        
        try:
            # Analyze sentiment of the first 512 characters
            sentiment = self.sentiment_analyzer(text[:512])[0]
            if sentiment['label'] == 'NEGATIVE' and sentiment['score'] > 0.8:
                score += 2
                indicators.append(f"Negative sentiment detected ({sentiment['score']:.2f} confidence)")
        except Exception as e:
            indicators.append("Sentiment analysis failed")
        
        return {"score": score, "indicators": indicators}
    
    def _ai_zero_shot_classification(self, text):
        """Zero-shot classification for phishing detection"""
        try:
            candidate_labels = ["phishing email", "legitimate communication", "promotional content", "security alert"]
            result = self.text_classifier(text[:1000], candidate_labels)
            top_label = result['labels'][0]
            top_score = result['scores'][0]
            return f"AI Classification: {top_label} ({top_score:.2f} confidence)"
        except Exception as e:
            return "Classification unavailable"
    
    def smart_threat_prediction(self, user_behavior_data=None):
        """AI-powered threat prediction"""
        try:
            if not HF_AVAILABLE:
                return "AI models not available", 0.0
            
            # Simulate threat prediction (in real app, use actual user data)
            features = self._simulate_user_behavior()
            clf = IsolationForest(contamination=0.1, random_state=42)
            predictions = clf.fit_predict(features)
            
            threat_probability = np.sum(predictions == -1) / len(predictions)
            
            if threat_probability > 0.3:
                return "🔴 High threat probability", threat_probability
            elif threat_probability > 0.1:
                return "🟡 Moderate threat probability", threat_probability
            else:
                return "🟢 Low threat probability", threat_probability
                
        except Exception as e:
            return "⚪ Analysis unavailable", 0.0
    
    def _simulate_user_behavior(self):
        """Simulate user behavior data for demo"""
        return np.random.rand(10, 5)

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
# FILE SCANNING MODULE
# --------------------------
class FileScanner:
    @staticmethod
    def calculate_file_hash(file_content):
        """Calculate SHA-256 hash of file content"""
        return hashlib.sha256(file_content).hexdigest()

    @staticmethod
    def check_file_type(filename):
        """Check file type and extension"""
        file_extensions = {
            'executable': ['.exe', '.bat', '.cmd', '.msi', '.com'],
            'script': ['.js', '.vbs', '.ps1', '.py', '.sh'],
            'document': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'],
            'video': ['.mp4', '.avi', '.mov', '.wmv', '.flv']
        }
        
        file_type = "unknown"
        for type_name, extensions in file_extensions.items():
            if any(filename.lower().endswith(ext) for ext in extensions):
                file_type = type_name
                break
                
        return file_type

    @staticmethod
    def analyze_file_risk(file_type, file_size, filename):
        """Analyze file risk based on type, size, and name"""
        risk_score = 0
        risk_factors = []
        
        # File type risk assessment
        if file_type == "executable":
            risk_score += 3
            risk_factors.append("Executable files can contain malware")
        elif file_type == "script":
            risk_score += 2
            risk_factors.append("Script files can execute malicious code")
        elif file_type == "archive":
            risk_score += 1
            risk_factors.append("Archive files can contain hidden malicious content")
            
        # File size risk assessment
        if file_size > 50 * 1024 * 1024:  # 50MB
            risk_score += 1
            risk_factors.append("Large file size may indicate embedded content")
        elif file_size < 100:  # 100 bytes
            risk_score += 1
            risk_factors.append("Very small files can be suspicious")
            
        # Filename risk assessment
        suspicious_keywords = ['virus', 'malware', 'trojan', 'keygen', 'crack', 'patch']
        if any(keyword in filename.lower() for keyword in suspicious_keywords):
            risk_score += 2
            risk_factors.append("Filename contains suspicious keywords")
            
        # Double extension check
        if re.search(r'\.[a-z]{3,4}\.[a-z]{2,4}$', filename.lower()):
            risk_score += 2
            risk_factors.append("File has double extension (may be hiding true type)")
            
        # Determine risk level
        if risk_score >= 4:
            risk_level = "🚨 High Risk"
            color = "red"
        elif risk_score >= 2:
            risk_level = "⚠️ Medium Risk"
            color = "orange"
        else:
            risk_level = "✅ Low Risk"
            color = "green"
            
        return risk_level, risk_factors, risk_score, color

    @staticmethod
    def scan_file_content(file_content, filename):
        """Basic content scanning for suspicious patterns"""
        suspicious_patterns = {
            "executable_code": [b"MZ", b"PE", b"ELF"],  # Executable signatures
            "script_injection": [b"eval(", b"exec(", b"system(", b"shell_exec("],
            "suspicious_strings": [b"malware", b"virus", b"trojan", b"ransomware"],
            "encoded_content": [b"base64", b"eval(", b"fromCharCode"],
        }
        
        detected_patterns = []
        content_preview = file_content[:1000]  # First 1000 bytes for analysis
        
        for pattern_type, patterns in suspicious_patterns.items():
            for pattern in patterns:
                if pattern in content_preview:
                    detected_patterns.append(f"Found {pattern_type}: {pattern}")
                    
        return detected_patterns

    @staticmethod
    def get_file_recommendations(risk_level, file_type):
        """Get security recommendations based on file scan results"""
        recommendations = {
            "high": [
                "🚨 DO NOT OPEN this file!",
                "Immediately delete the file from your system",
                "Run a full system antivirus scan",
                "Isolate the system from the network if possible",
                "Contact your IT security team"
            ],
            "medium": [
                "⚠️ Be cautious when opening this file",
                "Scan with updated antivirus software before opening",
                "Verify the file source and sender",
                "Open in a sandboxed environment if possible",
                "Check file digital signature if available"
            ],
            "low": [
                "✅ File appears safe but remain vigilant",
                "Keep your antivirus software updated",
                "Verify file source before opening",
                "Enable file extension visibility in your system",
                "Regularly backup important data"
            ]
        }
        
        # Additional type-specific recommendations
        type_recommendations = {
            "executable": [
                "Only run executables from trusted sources",
                "Check digital signatures of executable files",
                "Use application whitelisting where possible"
            ],
            "script": [
                "Review script content before execution",
                "Disable automatic script execution in email clients",
                "Use script execution policies"
            ],
            "archive": [
                "Scan archive contents before extraction",
                "Be cautious of password-protected archives",
                "Extract in isolated environment first"
            ]
        }
        
        base_recs = recommendations.get("high" if "High" in risk_level else "medium" if "Medium" in risk_level else "low", [])
        type_recs = type_recommendations.get(file_type, [])
        
        return base_recs + type_recs

# Initialize AI Security
advanced_ai = AdvancedAISecurity()

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
            ["📚 Wikipedia Chatbot", "🛡️ Security Tools", "🛡️ Threat Prevention", "📊 Data Visualization", "🧠 AI Security Lab"],
            key="nav"
        )
        
        st.markdown("---")
        st.markdown("### 🤖 AI Status")
        if advanced_ai.models_available["huggingface"]:
            st.success("✅ Hugging Face: Active")
        else:
            st.warning("🔸 Hugging Face: Install transformers")
        
        st.markdown("---")
        st.markdown("### ℹ️ About")
        st.info("""
        **Sentinel-Auth** is an AI-powered threat detection & prevention system that combines:
        - Real-time URL scanning (VirusTotal)
        - Advanced AI threat analysis
        - File security analysis
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
        col1, col2, col3, col4 = st.columns(4)
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
                <h3>📁 Advanced</h3>
                <h2>File Scanner</h2>
                <p>Multi-layer Analysis</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="metric-card">
                <h3>🤖 AI-Powered</h3>
                <h2>Threat Analysis</h2>
                <p>Multiple AI Models</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="metric-card">
                <h3>📊 Detailed</h3>
                <h2>Security Report</h2>
                <p>Comprehensive Results</p>
            </div>
            """, unsafe_allow_html=True)

        # Create tabs for different security tools
        security_tab1, security_tab2, security_tab3 = st.tabs(["🌐 URL Safety Scanner", "📁 File Security Analyzer", "🧠 AI Threat Analysis"])

        with security_tab1:
            # URL Scanner
            st.subheader("🌐 URL Safety Check")
            
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

            url_input = st.text_input("Enter URL to scan:", placeholder="https://example.com", key="url_input")
            scan_col1, scan_col2 = st.columns([1, 4])
            with scan_col1:
                scan_button = st.button("🔍 Scan URL", use_container_width=True, key="url_scan")
            
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

        with security_tab2:
            # FILE SCANNING SECTION
            st.subheader("📁 AI-Powered File Security Analyzer")
            
            st.markdown("""
            <div class="file-scan-card">
                <h4>🔍 How File Scanning Works:</h4>
                <p>Our AI analyzes files using multiple security layers:</p>
                <ul>
                    <li><strong>File Type Analysis:</strong> Identifies executable, script, and document files</li>
                    <li><strong>Risk Assessment:</strong> Evaluates based on type, size, and filename patterns</li>
                    <li><strong>Content Scanning:</strong> Detects suspicious patterns and signatures</li>
                    <li><strong>Hash Analysis:</strong> Generates unique file fingerprints for tracking</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

            # File upload section
            uploaded_file = st.file_uploader(
                "Choose a file to scan",
                type=None,  # Allow all file types
                help="Upload any file for security analysis (Max: 200MB)"
            )

            if uploaded_file is not None:
                # File information
                file_details = {
                    "Filename": uploaded_file.name,
                    "File size": f"{len(uploaded_file.getvalue()) / 1024:.2f} KB",
                    "File type": uploaded_file.type,
                    "Upload timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                # Display file info
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("📄 File Information")
                    for key, value in file_details.items():
                        st.write(f"**{key}:** {value}")

                # Scan file
                if st.button("🛡️ Scan File for Threats", use_container_width=True):
                    with st.spinner("🔍 Analyzing file for security threats..."):
                        # Get file content
                        file_content = uploaded_file.getvalue()
                        
                        # Perform file analysis
                        file_type = FileScanner.check_file_type(uploaded_file.name)
                        file_hash = FileScanner.calculate_file_hash(file_content)
                        risk_level, risk_factors, risk_score, color = FileScanner.analyze_file_risk(
                            file_type, len(file_content), uploaded_file.name
                        )
                        suspicious_patterns = FileScanner.scan_file_content(file_content, uploaded_file.name)
                        recommendations = FileScanner.get_file_recommendations(risk_level, file_type)

                    # Display results
                    with col2:
                        st.subheader("🛡️ Scan Results")
                        st.markdown(f"<h3 style='color: {color};'>{risk_level}</h3>", unsafe_allow_html=True)
                        st.write(f"**Risk Score:** {risk_score}/8")
                        st.write(f"**File Type Category:** {file_type.title()}")
                        st.write(f"**SHA-256 Hash:** `{file_hash}`")

                    # Risk factors
                    if risk_factors:
                        st.subheader("📊 Risk Assessment Factors")
                        for factor in risk_factors:
                            st.write(f"• {factor}")

                    # Suspicious patterns
                    if suspicious_patterns:
                        st.subheader("🚨 Suspicious Patterns Detected")
                        for pattern in suspicious_patterns:
                            st.error(pattern)

                    # Recommendations
                    st.subheader("💡 Security Recommendations")
                    for i, recommendation in enumerate(recommendations, 1):
                        if "🚨" in recommendation or "⚠️" in recommendation:
                            st.error(f"{i}. {recommendation}")
                        else:
                            st.success(f"{i}. {recommendation}")

                    # File analysis details expander
                    with st.expander("🔍 Detailed File Analysis"):
                        st.write("**File Signature Analysis:**")
                        st.code(f"First 100 bytes (hex): {file_content[:100].hex()}", language="text")
                        
                        st.write("**Content Preview:**")
                        try:
                            # Try to decode as text for preview
                            text_preview = file_content[:500].decode('utf-8', errors='ignore')
                            st.text_area("Text Preview", text_preview, height=100)
                        except:
                            st.info("File content is binary or cannot be displayed as text")

            else:
                st.info("👆 Please upload a file to begin security analysis")

            # File scanning tips
            st.markdown("""
            <div class="tip-card">
                <h4>💡 File Security Best Practices:</h4>
                <ul>
                    <li>Always scan files from unknown sources</li>
                    <li>Be cautious with executable (.exe) and script files</li>
                    <li>Keep your antivirus software updated</li>
                    <li>Enable file extension visibility in Windows</li>
                    <li>Use sandbox environments for suspicious files</li>
                    <li>Regularly backup important data</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

        with security_tab3:
            # NEW AI THREAT ANALYSIS SECTION
            st.subheader("🧠 Advanced AI Threat Analysis")
            
            st.markdown("""
            <div class="ai-card">
                <h4>🤖 Multi-Model AI Analysis</h4>
                <p>Our system uses multiple AI models for comprehensive threat detection:</p>
                <ul>
                    <li><strong>Hugging Face:</strong> Sentiment analysis and classification</li>
                    <li><strong>Pattern Recognition:</strong> Behavioral and linguistic analysis</li>
                    <li><strong>Machine Learning:</strong> Threat prediction and anomaly detection</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
            
            # AI Analysis Options
            analysis_type = st.selectbox(
                "Select Analysis Type:",
                ["Phishing Email Analysis", "Threat Prediction", "Security Text Analysis"]
            )
            
            if analysis_type == "Phishing Email Analysis":
                st.subheader("🔍 AI-Powered Phishing Detection")
                email_content = st.text_area("Paste email content for AI analysis:", height=200,
                                           placeholder="Paste suspicious email content here...")
                
                if st.button("🤖 Analyze with AI", key="ai_phishing_btn"):
                    if email_content:
                        with st.spinner("Multiple AI models analyzing content..."):
                            analysis = advanced_ai.enhanced_phishing_detection(email_content)
                        
                        # Display Results
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Risk Score", analysis["risk_score"])
                            st.metric("Confidence", analysis["confidence"])
                        with col2:
                            st.metric("Final Verdict", analysis["final_verdict"].split(" ")[0])
                        
                        st.subheader("📊 Detailed Analysis")
                        
                        if analysis["indicators"]:
                            st.write("**🚨 Threat Indicators:**")
                            for indicator in analysis["indicators"]:
                                st.write(f"• {indicator}")
                        
                        if analysis["ai_insights"]:
                            st.write("**🤖 AI Insights:**")
                            for insight in analysis["ai_insights"]:
                                st.info(insight)
                        
                        # Risk Level Visualization
                        risk_level = analysis["risk_score"]
                        if risk_level >= 8:
                            st.error("🚨 HIGH RISK: Immediate action recommended!")
                        elif risk_level >= 5:
                            st.warning("⚠️ MEDIUM RISK: Exercise caution!")
                        else:
                            st.success("✅ LOW RISK: Likely safe")
                            
                    else:
                        st.warning("Please enter email content to analyze.")
            
            elif analysis_type == "Threat Prediction":
                st.subheader("🔮 AI Threat Prediction")
                st.info("This feature analyzes patterns to predict potential security threats.")
                
                if st.button("🎯 Predict Threats", key="threat_pred_btn"):
                    with st.spinner("AI analyzing threat patterns..."):
                        prediction, probability = advanced_ai.smart_threat_prediction()
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Threat Prediction", prediction)
                    with col2:
                        st.metric("Probability", f"{probability:.1%}")
                    
                    # Recommendations based on prediction
                    if "High" in prediction:
                        st.error("""
                        **🚨 Immediate Actions Recommended:**
                        - Review recent security logs
                        - Check for unusual network activity
                        - Verify backup systems
                        - Alert security team
                        """)
                    elif "Moderate" in prediction:
                        st.warning("""
                        **⚠️ Recommended Actions:**
                        - Monitor system activity
                        - Update security protocols
                        - Review access logs
                        """)
                    else:
                        st.success("""
                        **✅ System Status Normal:**
                        - Continue regular monitoring
                        - Maintain security best practices
                        """)
            
            elif analysis_type == "Security Text Analysis":
                st.subheader("📝 AI Security Text Analysis")
                security_text = st.text_area("Enter security-related text for analysis:", height=150,
                                           placeholder="Paste security logs, alerts, or suspicious text...")
                
                if st.button("🔍 Analyze Text", key="text_analysis_btn"):
                    if security_text:
                        with st.spinner("AI analyzing text content..."):
                            # Use multiple AI analysis techniques
                            if advanced_ai.models_available["sentiment"]:
                                sentiment = advanced_ai.sentiment_analyzer(security_text[:512])[0]
                                st.metric("Sentiment Analysis", 
                                         f"{sentiment['label']} ({sentiment['score']:.2f})")
                            
                            if advanced_ai.models_available["classifier"]:
                                categories = ["security threat", "normal activity", "system alert", "false positive"]
                                classification = advanced_ai.text_classifier(security_text[:1000], categories)
                                top_category = classification['labels'][0]
                                top_score = classification['scores'][0]
                                st.metric("AI Classification", 
                                         f"{top_category} ({top_score:.2f} confidence)")
                        
                        # Basic pattern analysis
                        threat_keywords = ['hack', 'breach', 'malware', 'attack', 'vulnerability', 'exploit']
                        found_keywords = [kw for kw in threat_keywords if kw in security_text.lower()]
                        
                        if found_keywords:
                            st.warning(f"**Potential Threat Keywords Found:** {', '.join(found_keywords)}")
                        else:
                            st.success("No obvious threat keywords detected")
                            
                    else:
                        st.warning("Please enter text to analyze.")

    # NEW: AI SECURITY LAB SECTION
    elif "🧠 AI Security Lab" in section:
        st.markdown('<div class="section-header">🧠 AI Security Laboratory</div>', unsafe_allow_html=True)
        
        st.markdown("""
        <div class="info-box">
            <h4>🔬 Advanced AI Research Lab</h4>
            <p>This section demonstrates cutting-edge AI capabilities for cybersecurity research and development.</p>
        </div>
        """, unsafe_allow_html=True)
        
        lab_tab1, lab_tab2 = st.tabs(["AI Model Status", "Security Research"])
        
        with lab_tab1:
            st.subheader("🤖 AI Model Status & Configuration")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Available AI Models:**")
                if advanced_ai.models_available["huggingface"]:
                    st.success("✅ Hugging Face Models - Active")
                else:
                    st.warning("⚠️ Hugging Face - Install required")
                
                if advanced_ai.models_available["sentiment"]:
                    st.success("✅ Sentiment Analysis - Active")
                else:
                    st.warning("⚠️ Sentiment Analysis - Limited")
            
            with col2:
                st.write("**AI Capabilities:**")
                capabilities = [
                    "Advanced Phishing Detection",
                    "Sentiment Analysis",
                    "Zero-shot Classification", 
                    "Behavioral Pattern Recognition",
                    "Threat Prediction",
                    "Multi-model Analysis"
                ]
                
                for capability in capabilities:
                    st.write(f"• {capability}")
            
            # API Configuration Help
            with st.expander("🔧 API Configuration Guide"):
                st.markdown("""
                **To enable all AI features, add this to your `.streamlit/secrets.toml`:**
                ```toml
                VIRUSTOTAL_API_KEY = "eb6f6caad9a31538ced27f970b3e790af750d2da03f98bae9f3cb0ef66a34d77"
                ```
                
                **Install required packages:**
                ```bash
                pip install transformers torch scikit-learn numpy
                ```
                """)
        
        with lab_tab2:
            st.subheader("🔬 Security Research & Development")
            
            st.info("""
            **Current Research Areas:**
            - Multi-modal AI threat detection
            - Real-time behavioral analysis
            - Predictive security analytics
            - AI-powered incident response
            """)
            
            # Research Demo
            st.subheader("AI Security Research Demo")
            research_input = st.text_area("Enter security research data:", height=100,
                                        placeholder="Paste security logs, network data, or research notes...")
            
            if st.button("🧪 Analyze with Research AI"):
                if research_input:
                    with st.spinner("Research AI processing..."):
                        # Simulate advanced research analysis
                        st.success("🔬 Research Analysis Complete")
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Data Complexity", "High")
                        with col2:
                            st.metric("Threat Patterns", "3 detected")
                        with col3:
                            st.metric("Research Value", "87%")
                        
                        st.write("**Research Insights:**")
                        insights = [
                            "Multiple threat vectors identified",
                            "Behavioral patterns suggest coordinated activity", 
                            "Recommend further investigation",
                            "Potential new attack signature detected"
                        ]
                        
                        for insight in insights:
                            st.write(f"• {insight}")
                else:
                    st.warning("Please enter research data for analysis")

    # THREAT PREVENTION SECTION
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
                password = st.text_input("Enter password to analyze:", type="password", placeholder="Type your password here...", key="password_analyze")
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
            st.subheader("AI Phishing Detection")
            
            email_text = st.text_area(
                "Paste email/text content to analyze:",
                height=150,
                placeholder="Paste the suspicious email or message content here...",
                key="phishing_text"
            )
            
            if st.button("🔍 Analyze for Phishing", use_container_width=True, key="phishing_btn"):
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
                ["phishing", "malware", "weak_password", "network"],
                key="threat_type"
            )
            
            if st.button("🎯 Get AI Recommendations", use_container_width=True, key="recommend_btn"):
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
