import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from utils import fetch_cve_data, filter_cves_with_cpe
from urllib.parse import urlencode

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

# Get query parameters
query_params = st.experimental_get_query_params()
default_start = datetime.now() - timedelta(days=1)
default_end = datetime.now()

# Date selection
col1, col2 = st.columns(2)
with col1:
    start_date = st.date_input(
        "Start Date",
        value=datetime.strptime(query_params.get('start_date', [default_start.strftime("%Y-%m-%d")])[0], "%Y-%m-%d") if 'start_date' in query_params else default_start
    )
with col2:
    end_date = st.date_input(
        "End Date",
        value=datetime.strptime(query_params.get('end_date', [default_end.strftime("%Y-%m-%d")])[0], "%Y-%m-%d") if 'end_date' in query_params else default_end
    )

# Convert dates to datetime
start_datetime = datetime.combine(start_date, datetime.min.time())
end_datetime = datetime.combine(end_date, datetime.max.time())

# Update query parameters
new_params = {
    'start_date': start_date.strftime("%Y-%m-%d"),
    'end_date': end_date.strftime("%Y-%m-%d")
}
st.experimental_set_query_params(**new_params)

# Generate shareable link
base_url = st.experimental_get_query_params().get('host_url', [''])[0]
if not base_url:
    base_url = "https://your-replit-url.repl.co"  # This will be replaced with the actual Replit URL
share_url = f"{base_url}?{urlencode(new_params)}"

# Add share button
st.sidebar.markdown("### Share Results")
st.sidebar.markdown("Share this link to show others your search results:")
st.sidebar.code(share_url, language="text")
if st.sidebar.button("📋 Copy Link"):
    st.sidebar.success("Link copied to clipboard!")
    st.write(f'<script>navigator.clipboard.writeText("{share_url}");</script>', unsafe_allow_html=True)

# Fetch data button
if st.button("Fetch CVE Data"):
    with st.spinner("Fetching data from NVD..."):
        success, result = fetch_cve_data(start_datetime, end_datetime)

        if success:
            filtered_cves = filter_cves_with_cpe(result)

            if filtered_cves:
                # Convert to DataFrame for better display
                df = pd.DataFrame(filtered_cves)

                # Display summary statistics
                st.subheader("Summary Statistics")
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Total CVEs Found", len(filtered_cves))
                with col2:
                    avg_severity = pd.to_numeric(df['severity'], errors='coerce').mean()
                    st.metric("Average Severity Score", f"{avg_severity:.2f}")

                # Display the data
                st.subheader("CVE Details")

                # Create expandable sections for each CVE
                for cve in filtered_cves:
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