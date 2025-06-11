from datetime import datetime, timedelta
import requests
import sys
import pandas as pd
import csv
import time

def translate_vendor(input_vendor: str):
    with open("translation.csv", 'r') as translator:
        df = pd.read_csv(translator)
        for i, vendor in enumerate(df['Vendor']):
            if vendor == input_vendor:
                return df['translation'][i]
    return 'no_match'


def fetch_CVEs_with_split(vendor, engine_time, split_size=5_000_000, end_date: datetime=None):
    results = []
    if vendor == 'no_match':
        return pd.DataFrame()

    if end_date is None:
        end_date = datetime.now()

    # How many seconds ago is end_date from now?
    end_time_s = int((datetime.now() - end_date).total_seconds())
    
    start = engine_time 
    while start > end_time_s:
        end = max(start - split_size, end_time_s)
        df = fetch_CVEs(vendor, start_time_s=start, end_time_s=end)
        if df is not None:
            results.append(df)
        start = end  # move further toward present (i.e., decrease "seconds ago")
        time.sleep(1) # Sleep to avoid too many requests

    return pd.concat(results, ignore_index=True) if results else pd.DataFrame()


def fetch_CVEs(vendor: str, start_time_s: int, end_time_s = None):
    # Use NVD API to fetch CVEs
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    start_date = (datetime.now() - timedelta(seconds=start_time_s)).strftime("%Y-%m-%dT%H:%M:%S")
    if not end_time_s:
        end_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    else:
        end_date = (datetime.now() - timedelta(seconds=end_time_s)).strftime("%Y-%m-%dT%H:%M:%S")

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
                'Published': cve['cve']['published'],
                'CVSS_Score': None,
                'Severity': None,
                'CVSS_Version': None,
                'Exploitablity_Score': None
            }
            
            if 'metrics' in cve['cve']:
                if 'cvssMetricV31' in cve['cve']['metrics']:
                    cve_data['CVSS_Score'] = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                    cve_data['Severity'] = cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                    cve_data['CVSS_Version'] = '3.1'
                    cve_data['Exploitablity_Score'] = cve['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore']
                elif 'cvssMetricV2' in cve['cve']['metrics']:
                    cve_data['CVSS_Score'] = cve['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                    cve_data['Severity'] = cve['cve']['metrics']['cvssMetricV2'][0]['cvssData']['severity']
                    cve_data['CVSS_Version'] = '2.0'
                    cve_data['Exploitablity_Score'] = cve['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore']
            
            data.append(cve_data)
    else:
        print(f"Error: {res.status_code}")
    
    # Create DataFrame
    df = pd.DataFrame(data)
    #print("\nDataFrame:")
    #print(df)
    return df

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python cve_matching.py <engine time> <option> <vendor name> ")
        print("option types:  \n",\
            "<none> - take vendor name as is\n",\
            "'-t' - translate vendor name via translation.csv file\n"\
            "'-a' - run for all vendors in translation file")        
        sys.exit(1)
    
    engine_time = int(float(sys.argv[1]))
    #Runs for vendor name translated to searchable name in translation file
    if sys.argv[2] == '-t' and len(sys.argv) == 4:
        with open("translation.csv", 'r') as translator:
            vendor_name = sys.argv[3]
            df = pd.read_csv(translator)
            for i, vendor in enumerate(df['Vendor']):
                if vendor == vendor_name:
                     fetch_CVEs(df['translation'][i], engine_time)
                     break
    #Runs for all vendors present in translation file
    elif sys.argv[2] == '-a' and len(sys.argv) == 3:
        with open("translation.csv", 'r') as translator:
            df = pd.read_csv(translator)
            for row in df['translation']:
                        fetch_CVEs(row, engine_time)
    #Takes vendor name and runs as is
    elif len(sys.argv) == 3:
        vendor = sys.argv[2]
        fetch_CVEs(vendor, engine_time)
       