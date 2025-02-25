import requests
from datetime import datetime, timedelta
import json

def format_datetime(dt):
    """Format datetime object to ISO format required by NVD API."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")

def fetch_cve_data(start_date=None, end_date=None):
    """
    Fetch CVE data from NIST NVD API.
    
    Args:
        start_date (datetime): Start date for CVE search
        end_date (datetime): End date for CVE search
    
    Returns:
        tuple: (success (bool), data/error message (dict/str))
    """
    if not start_date:
        start_date = datetime.now() - timedelta(days=1)
    if not end_date:
        end_date = datetime.now()

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "lastModStartDate": format_datetime(start_date),
        "lastModEndDate": format_datetime(end_date)
    }

    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        return True, response.json()
    except requests.RequestException as e:
        return False, f"Error fetching data: {str(e)}"

def filter_cves_with_cpe(cve_data):
    """
    Filter CVEs to only include those with at least one CPE.
    
    Args:
        cve_data (dict): Raw CVE data from NVD API
    
    Returns:
        list: Filtered list of CVEs
    """
    filtered_cves = []
    
    for vulnerability in cve_data.get('vulnerabilities', []):
        cve = vulnerability.get('cve', {})
        configurations = cve.get('configurations', [])
        
        has_cpe = False
        cpe_nodes = []
        
        for config in configurations:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    has_cpe = True
                    cpe_nodes.append(cpe_match.get('criteria', ''))
        
        if has_cpe:
            cve_entry = {
                'id': cve.get('id', ''),
                'description': cve.get('descriptions', [{}])[0].get('value', 'No description available'),
                'published': cve.get('published', ''),
                'lastModified': cve.get('lastModified', ''),
                'severity': get_severity(cve),
                'cpe_nodes': cpe_nodes
            }
            filtered_cves.append(cve_entry)
    
    return filtered_cves

def get_severity(cve):
    """Extract severity information from CVE data."""
    metrics = cve.get('metrics', {})
    cvss_metrics = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
    
    if cvss_metrics:
        return cvss_metrics[0].get('cvssData', {}).get('baseScore', 'N/A')
    return 'N/A'
