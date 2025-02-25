import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from utils import fetch_cve_data, filter_cves_with_cpe

# Page configuration
st.set_page_config(
    page_title="CVE Data Explorer",
    page_icon="🔒",
    layout="wide"
)

# Title and description
st.title("🔒 CVE Data Explorer")
st.markdown("""
This application fetches and filters CVE (Common Vulnerabilities and Exposures) data 
from the NIST National Vulnerability Database (NVD) API. It shows only CVEs that have 
at least one CPE (Common Platform Enumeration) associated with them.
""")

# Date selection
col1, col2 = st.columns(2)
with col1:
    start_date = st.date_input(
        "Start Date",
        value=datetime.now() - timedelta(days=1)
    )
with col2:
    end_date = st.date_input(
        "End Date",
        value=datetime.now()
    )

# Convert dates to datetime
start_datetime = datetime.combine(start_date, datetime.min.time())
end_datetime = datetime.combine(end_date, datetime.max.time())

# Fetch data button
if st.button("Fetch CVE Data"):
    with st.spinner("Fetching data from NVD..."):
        success, result = fetch_cve_data(start_datetime, end_datetime)

        if success:
            filtered_cves = filter_cves_with_cpe(result)

            if filtered_cves:
                # Convert to DataFrame for better display
                df = pd.DataFrame(filtered_cves)

                # Convert published date to datetime for sorting
                df['published_dt'] = pd.to_datetime(df['published'])
                df = df.sort_values('published_dt', ascending=False)

                # Display summary statistics
                st.subheader("Summary Statistics")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total CVEs Found", len(filtered_cves))
                with col2:
                    avg_severity = pd.to_numeric(df['severity'], errors='coerce').mean()
                    st.metric("Average Severity Score", f"{avg_severity:.2f}")
                with col3:
                    new_cves = len(df[df['published_dt'] > (datetime.now() - timedelta(days=1))])
                    st.metric("New CVEs (Last 24h)", new_cves)

                # Display latest CVEs section
                st.subheader("🆕 Latest Critical CVEs")
                st.markdown("**Most recently published critical vulnerabilities (CVSS Score >= 9.0):**")

                # Filter for critical CVEs (severity >= 9.0)
                critical_df = df[pd.to_numeric(df['severity'], errors='coerce') >= 9.0]
                critical_df = critical_df.sort_values('published_dt', ascending=False)

                if not critical_df.empty:
                    # Display the 10 most recent critical CVEs in a special format
                    for _, cve in critical_df.head(10).iterrows():
                        with st.container():
                            st.markdown(f"""
                            <div style='padding: 10px; border-left: 5px solid #ff0000; margin-bottom: 10px; background-color: rgba(255, 0, 0, 0.05);'>
                                <h3 style='color: #ff0000; margin: 0;'>{cve['id']} - Critical Severity</h3>
                                <p><strong>Severity Score:</strong> {cve['severity']}</p>
                                <p><strong>Published:</strong> {cve['published']}</p>
                                <p>{cve['description']}</p>
                                <p><strong>Affected Components:</strong></p>
                                <pre style='background-color: #f0f0f0; padding: 5px;'>{chr(10).join(cve['cpe_nodes'][:3])}{'...' if len(cve['cpe_nodes']) > 3 else ''}</pre>
                            </div>
                            """, unsafe_allow_html=True)
                else:
                    st.info("No critical severity CVEs found in the specified date range.")

                # Display all CVE details
                st.subheader("📋 All CVE Details")

                # Create expandable sections for each CVE
                for _, cve in df.iterrows():
                    with st.expander(f"{cve['id']} - Severity: {cve['severity']}"):
                        st.markdown(f"**Description:** {cve['description']}")
                        st.markdown(f"**Published:** {cve['published']}")
                        st.markdown(f"**Last Modified:** {cve['lastModified']}")
                        st.markdown("**Associated CPEs:**")
                        for cpe in cve['cpe_nodes']:
                            st.code(cpe)
            else:
                st.warning("No CVEs with CPE entries found in the specified date range.")
        else:
            st.error(result)  # Display error message

# Add footer with information
st.markdown("---")
st.markdown("""
<div style='text-align: center'>
    <p>Data source: NIST National Vulnerability Database (NVD) API</p>
    <p>Updated in real-time | Displaying CVEs with CPE entries only</p>
</div>
""", unsafe_allow_html=True)