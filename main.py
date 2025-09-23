import streamlit as st
import wikipedia
import streamlit_authenticator as stauth
import requests
import pandas as pd

# Debug: Show loaded secrets for verification (remove in production)
st.write("Secrets loaded:", dict(st.secrets))

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
st.title("🌐Sentinel-Auth")

# --------------------------
# LOGIN FORM
# --------------------------
name, authentication_status, username = authenticator.login(fields={"form_name": "Login"}, location="main")

if authentication_status:
    st.sidebar.success(f"✅ Welcome {name}")
    authenticator.logout("Logout", "sidebar")

    section = st.sidebar.radio(
        "Select Section",
        ["Wikipedia Chatbot", "Security Tools", "Data Visualization"]
    )

    # Wikipedia Chatbot Section
    if section == "Wikipedia Chatbot":
        st.title("📚 Wikipedia Chatbot")
        if "messages" not in st.session_state:
            st.session_state.messages = []

        def get_wikipedia_summary(query):
            try:
                results = wikipedia.search(query)
                if not results:
                    return "Sorry, I couldn't find anything on that topic."
                summary = wikipedia.summary(results[0], sentences=2, auto_suggest=False, redirect=True)
                return summary
            except wikipedia.DisambiguationError as e:
                return f"Your query is ambiguous, did you mean: {', '.join(e.options[:5])}?"
            except wikipedia.PageError:
                return "Sorry, I couldn't find a page matching your query."
            except Exception:
                return "Oops, something went wrong."

        user_input = st.text_input("Ask me anything:")
        if user_input:
            st.session_state.messages.append({"role": "user", "content": user_input})
            bot_response = get_wikipedia_summary(user_input)
            st.session_state.messages.append({"role": "bot", "content": bot_response})
        for msg in st.session_state.messages:
            if msg["role"] == "user":
                st.markdown(f"**You:** {msg['content']}")
            else:
                st.markdown(f"**Bot:** {msg['content']}")

    # Security Tools Section
    elif section == "Security Tools":
        st.title("🛡️ AI Threat Detection and Prevention")
        st.write("Check if a URL is safe using VirusTotal API.")

        # Prefer to load from secrets.toml
        try:
            api_key = st.secrets["VIRUSTOTAL_API_KEY"]
        except KeyError:
            # fallback inline key (not recommended for production)
            api_key = "eb6f6caad9a31538ced27f970b3e790af750d2da03f98bae9f3cb0ef66a34d77"

        import base64, time

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

        url_input = st.text_input("Enter URL to check:")
        if st.button("Check URL"):
            if not url_input:
                st.error("Please enter a URL.")
            elif not (url_input.startswith("http://") or url_input.startswith("https://")):
                st.error("URL must start with http:// or https://")
            else:
                safe, details = check_url_safety(url_input)
                if safe is None:
                    st.error(details)
                elif safe:
                    st.success("✅ This URL is safe.")
                else:
                    st.error("⚠️ This URL is unsafe!")
                st.json(details)


    # Data Visualization Section
    elif section == "Data Visualization":
        st.title("📊 Data Visualization")
        try:
            data = pd.read_csv('data/cybersecurity_intrusion_data.csv')  # Correct path
            # Visualize Attack vs Non-Attack Distribution
            st.subheader("Attack vs Non-Attack Distribution")
            attack_counts = data['attack_detected'].value_counts()
            st.bar_chart(attack_counts)

            # Visualize Protocol Usage
            st.subheader("Network Protocol Usage")
            protocol_counts = data['protocol_type'].value_counts()
            st.bar_chart(protocol_counts)

            # Preview Data
            st.subheader("Preview Data")
            st.dataframe(data.head())
        except Exception as e:
            st.error(f"Error loading or visualizing data: {e}")

else:
    if authentication_status is False:
        st.error("❌ Username/password is incorrect")
    elif authentication_status is None:
        st.warning("ℹ️ Please enter your username and password")
