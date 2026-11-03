
import streamlit as st
from detector import detect_phishing

st.set_page_config(
    page_title="Phishing Website Detector",
    page_icon="🛡️",
    layout="wide"
)

# Custom styling
st.markdown("""
<style>
.main {
    background-color: #0e1117;
}
h1 {
    color: #00d4ff;
    text-align: center;
}
.subtitle {
    text-align: center;
    color: #aaaaaa;
    font-size: 18px;
}
.result-box {
    padding: 20px;
    border-radius: 12px;
    background-color: #202938;
    margin-top: 20px;
}
</style>
""", unsafe_allow_html=True)

# Header
st.title("🛡️ PHISHING WEBSITE DETECTOR")

st.markdown(
    '<p class="subtitle">Cybersecurity URL Analysis Dashboard</p>',
    unsafe_allow_html=True
)

st.divider()

# Sidebar
st.sidebar.title("🛡️ Navigation")
st.sidebar.write("Phishing Detection System")
st.sidebar.info("Analyze suspicious website URLs.")

# Main section
st.subheader("🔍 Website Security Scanner")

st.write(
    "Enter a website URL below to analyze its "
    "potential phishing indicators."
)

url = st.text_input(
    "Website URL",
    placeholder="https://example.com"
)

if st.button("🚀 SCAN WEBSITE", type="primary"):

    if not url.strip():
        st.warning("Please enter a website URL.")

    else:
        result = detect_phishing(url)

        score = result["risk_score"]
        status = result["status"]

        st.divider()

        st.subheader("📊 Security Analysis Results")

        col1, col2 = st.columns(2)

        with col1:
            st.metric(
                "Risk Score",
                f"{score}/100"
            )

        with col2:
            st.metric(
                "Security Status",
                status
            )

        st.progress(score / 100)

        if status == "High risk":
            st.error("🚨 High Risk Website")
        elif status == "Medium risk":
            st.warning("⚠️ Medium Risk Website")
        elif status == "Low risk":
            st.success("✅ Low Risk Indicators")
        else:
            st.error("Invalid URL")

        st.subheader("⚠️ Detection Details")

        for warning in result["warnings"]:
            st.write("•", warning)

        st.info(
            "This is a basic heuristic scanner. "
            "A low score does not guarantee that a website is safe."
        )

st.divider()

# Footer
st.markdown(
    "<center>Cybersecurity Project | Phishing Detection System</center>",
    unsafe_allow_html=True
)
