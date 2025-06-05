from datetime import datetime, timedelta
import requests
import pandas as pd


def fetch_CVEs(vendor: str, time_seconds: int):
    
    # Use NVD API to fetch CVEs
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start_date = (datetime.now() - timedelta(seconds=time_seconds)).strftime("%Y-%m-%dT%H:%M:%S")
    end_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    params = {
        'keywordSearch': vendor,
        'pubStartDate': start_date,
        'pubEndDate': end_date
    }
    data = []
    res = requests.get(base_url, params=params)
    if res.status_code == 200:
        cves = res.json()['vulnerabilities']
        for cve in cves:
            cve_data = {
                'CVE_ID': cve['cve']['id'],
                'Description': cve['cve']['descriptions'][0]['value'],
                'CVSS_Score': None,
                'Severity': None,
                'CVSS_Version': None
            }
            
            if 'metrics' in cve['cve']:
                if 'cvssMetricV31' in cve['cve']['metrics']:
                    cve_data['CVSS_Score'] = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    cve_data['Severity'] = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                    cve_data['CVSS_Version'] = '3.1'
                elif 'cvssMetricV2' in cve['cve']['metrics']:
                    cve_data['CVSS_Score'] = cve['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                    cve_data['Severity'] = cve['cve']['metrics']['cvssMetricV2'][0]['cvssData']['severity']
                    cve_data['CVSS_Version'] = '2.0'
            
            data.append(cve_data)
    else:
        print(f"Error: {res.status_code}")
    
    # Create DataFrame
    df = pd.DataFrame(data)
    print("\nDataFrame:")
    print(df)

if __name__ == "__main__":
    
    fetch_CVEs('fortinet', 1000000)