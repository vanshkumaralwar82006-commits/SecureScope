import streamlit as st
import pandas as pd
import plotly.express as px
from scanner import scan_website, findings_to_dataframe, make_html_report

st.set_page_config(page_title="SecureScope | Web Security Audit", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .stApp { background: linear-gradient(135deg, #081321 0%, #101f35 55%, #0b1525 100%); color: #edf4ff; }
    [data-testid="stSidebar"] { background: #0a1422; }
    .hero { padding: 1.35rem 1.5rem; border: 1px solid #254566; border-radius: 18px;
            background: linear-gradient(110deg, rgba(21,54,84,.9), rgba(12,27,46,.95)); margin-bottom: 1rem; }
    .hero h1 { margin: 0; color: #f4f8ff; font-size: 2.2rem; }
    .hero p { color: #b9cce4; margin-bottom: 0; }
    .small-note { color: #a9bdd5; font-size: .88rem; }
    div[data-testid="stMetric"] { background: rgba(22,42,65,.72); border: 1px solid #25415e; padding: 14px; border-radius: 14px; }
</style>
""", unsafe_allow_html=True)

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

with st.sidebar:
    st.markdown("## 🛡️ SecureScope")
    st.caption("Automated Web Security Scanner")
    page = st.radio("Navigation", ["Security Scanner", "How It Works", "Test Examples", "About & Limitations"])
    st.divider()
    st.caption("Defensive checks only")
    st.caption("Scan only sites you own or have permission to assess.")

if page == "Security Scanner":
    st.markdown("""
    <div class="hero">
      <h1>SecureScope</h1>
      <p>Understand basic web security configuration through clear, explainable checks.</p>
    </div>
    """, unsafe_allow_html=True)
    st.warning("Authorization required: scan only a website you own or are explicitly permitted to test. This tool performs a small number of ordinary HTTP requests; it is not a penetration tester.")
    url = st.text_input("Website URL", placeholder="https://example.com")
    c1, c2 = st.columns([1, 3])
    with c1:
        run = st.button("Run security check", type="primary", use_container_width=True)
    with c2:
        st.markdown('<p class="small-note">Checks HTTPS, selected response headers, and basic CORS response behavior. No exploitation or brute force.</p>', unsafe_allow_html=True)

    if run:
        with st.spinner("Checking website configuration..."):
            try:
                st.session_state.scan_result = scan_website(url)
            except Exception as e:
                st.error(str(e))
                st.session_state.scan_result = None

    result = st.session_state.scan_result
    if result:
        st.divider()
        score = result["score"]
        risk = result["risk"]
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Security score", f"{score}/100")
        m2.metric("Risk category", risk)
        m3.metric("Checks recorded", len(result["findings"]))
        m4.metric("Target", result["final_url"][:28] + ("…" if len(result["final_url"]) > 28 else ""))

        st.subheader("Findings")
        df = findings_to_dataframe(result["findings"])
        st.dataframe(df, use_container_width=True, hide_index=True)
        chart_col, advice_col = st.columns([1, 1])
        with chart_col:
            counts = df["Severity"].value_counts().rename_axis("Severity").reset_index(name="Count")
            order = [x for x in ["High", "Medium", "Low", "Info"] if x in counts["Severity"].tolist()]
            counts["Severity"] = pd.Categorical(counts["Severity"], categories=order, ordered=True)
            counts = counts.sort_values("Severity")
            fig = px.bar(counts, x="Severity", y="Count", title="Findings by severity", text="Count")
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                              font_color="#e8f0fc", margin=dict(l=10,r=10,t=50,b=10))
            st.plotly_chart(fig, use_container_width=True)
        with advice_col:
            st.subheader("Recommended next steps")
            for item in result["recommendations"]:
                st.markdown(f"- {item}")
            st.caption("A score is an educational indicator based only on the checks shown here. It is not a certification or proof that a site is safe.")

        html = make_html_report(result)
        st.download_button("Download HTML report", data=html, file_name="securescope_report.html", mime="text/html")
        st.download_button("Download CSV findings", data=df.to_csv(index=False).encode("utf-8"),
                           file_name="securescope_findings.csv", mime="text/csv")

elif page == "How It Works":
    st.markdown("## How SecureScope works")
    st.markdown("""
    1. **Validate input:** checks the URL format and allows only HTTP/HTTPS.
    2. **Request headers:** sends one ordinary GET request with a short timeout.
    3. **Inspect configuration:** checks HTTPS and selected security headers.
    4. **Check basic CORS behavior:** sends a benign request with a test `Origin` header and observes the response.
    5. **Explain results:** assigns simple severity labels and recommendations.
    6. **Export:** creates an HTML summary and CSV table.

    The tool does not log in, crawl pages, exploit vulnerabilities, scan ports, or attempt to bypass controls.
    """)
elif page == "Test Examples":
    st.markdown("## Safe demonstration cases")
    st.info("For a live demo, use a domain you own or a deliberately provided training environment. The examples below describe expected logic, not claims about live websites.")
    examples = pd.DataFrame([
        {"Case": "HTTPS + recommended headers present", "Expected outcome": "Fewer findings; stronger configuration score"},
        {"Case": "HTTP URL", "Expected outcome": "HTTPS transport warning"},
        {"Case": "Missing Content-Security-Policy", "Expected outcome": "Header recommendation"},
        {"Case": "Missing X-Content-Type-Options", "Expected outcome": "Low-severity recommendation"},
        {"Case": "CORS response reflects an arbitrary Origin", "Expected outcome": "Review finding; context is required"},
        {"Case": "Network timeout / blocked request", "Expected outcome": "Show a clear error; no score"},
    ])
    st.dataframe(examples, use_container_width=True, hide_index=True)
elif page == "About & Limitations":
    st.markdown("## About this project")
    st.write("SecureScope is a beginner-friendly educational prototype aligned with the internship topic: Automated Web Scanner.")
    st.markdown("""
    **What it can do**
    - Review a small set of HTTP response headers.
    - Identify whether the final URL uses HTTPS.
    - Observe basic CORS response behavior.
    - Export results.

    **What it cannot prove**
    - That a website is secure or vulnerable overall.
    - That a missing header is automatically exploitable.
    - That a CORS response is exploitable in every browser or application context.
    - That a scan covers every route, API, server, or configuration.

    **Responsible use:** only assess systems for which you have explicit permission. Do not submit private URLs, credentials, tokens, or sensitive data.
    """)
    st.caption("Project: SecureScope | Python + Streamlit + Requests + Plotly")
