import requests
from datetime import datetime, timedelta
import pandas as pd

def analyze_cve_dates():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Use current date and previous day
    end_date = datetime.now()
    start_date = end_date - timedelta(days=1)

    params = {
        "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
        "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    }

    try:
        print("Fetching CVE data...")
        print(f"Using date range: {start_date} to {end_date}")
        response = requests.get(url, params=params, timeout=30)
        print(f"Response status code: {response.status_code}")

        if response.status_code != 200:
            print(f"Error: API returned status code {response.status_code}")
            print(f"Response text: {response.text}")
            return

        data = response.json()
        print(f"Successfully retrieved data. Total vulnerabilities: {len(data.get('vulnerabilities', []))}")

        # Extract modification dates
        mod_dates = []
        for vuln in data.get('vulnerabilities', []):
            last_mod = vuln.get('cve', {}).get('lastModified')
            if last_mod:
                mod_dates.append(pd.to_datetime(last_mod))

        if mod_dates:
            newest = max(mod_dates)
            oldest = min(mod_dates)
            print("\nResults:")
            print(f"Newest modification date: {newest}")
            print(f"Oldest modification date: {oldest}")
            print(f"Total CVEs analyzed: {len(mod_dates)}")

            # Additional time difference analysis
            time_span = newest - oldest
            print(f"\nTime span between oldest and newest: {time_span}")
        else:
            print("No CVEs found in the date range")

    except requests.Timeout:
        print("Error: Request timed out after 30 seconds")
    except requests.RequestException as e:
        print(f"Network error: {str(e)}")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    analyze_cve_dates()