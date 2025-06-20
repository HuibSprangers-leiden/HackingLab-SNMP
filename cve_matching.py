from datetime import datetime, timedelta
import requests
import sys
import pandas as pd
import time

def translate_vendor(input_vendor: str):
    """ Translates vendor name to a 'searchable' name for the NIST API' all supported vendors are in config/translation.csv

    Args:
        input_vendor (str): The vendor string as given by the parsing script

    Returns:
        str: The translated vendor name
    """
    with open('config/translation.csv', 'r') as translator:
        df = pd.read_csv(translator)
        for i, vendor in enumerate(df['Vendor']):
            if vendor == input_vendor:
                return df['translation'][i]
    return 'no_match'


def fetch_CVEs_with_split(vendor, engine_time, split_size=5_000_000, end_date: datetime=None):
    """ Fetches all CVEs of a given vendor for all dates starting from 'engine_time' seconds ago. 
    If an end_date is given it marks the end of the search window.

    Args:
        vendor (str): the (translated) vendor name
        engine_time (int): Oldest engine time in seconds
        split_size (int, optional): Controls the max time window in seconds to split the request. Defaults to 5_000_000.
        end_date (datetime, optional): The end date of the time window. Defaults to None.

    Returns:
        pd.Dataframe: A dataframe with all the CVE data for the given vendor
    """
    results = []
    if vendor == 'no_match':
        print(f'Did not fetch any data for {vendor}')
        return pd.DataFrame()

    if end_date is None:
        end_date = datetime.now()

    # How many seconds ago is end_date from now?
    end_time_s = int((datetime.now() - end_date).total_seconds())
    print(f'Fetching CVEs for {vendor}, from {engine_time}s ago until {end_date}')
    print('This might take a while...')
    
    start = engine_time 
    count = 0
    while start > end_time_s:
        # Respect 5 requests/30s limit of NIST api
        if count == 5:
            time.sleep(26)
            count = 0
        
        end = max(start - split_size, end_time_s)
        df = fetch_CVEs(vendor, start_time_s=start, end_time_s=end)
        if df is not None:
            results.append(df)
        start = end  # move further toward present (i.e., decrease "seconds ago")
        count += 1

    return pd.concat(results, ignore_index=True) if results else pd.DataFrame()


def fetch_CVEs(vendor: str, start_time_s: int, end_time_s = None):
    """ Fetches all CVEs for a given vendor in a time window between 'start_time_s' seconds ago and 'end_time_s' seconds ago.

    Args:
        vendor (str): The vendor name
        start_time_s (int): Time since the start of the search in seconds ago.
        end_time_s (_type_, optional): Time indicating the end of the search in seconds ago. Defaults to None, and the current time is taken.

    Returns:
        pd.Dataframe: A dataframe with all the CVE data for the given vendor
    """
    # Use NVD API to fetch CVEs
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

    start_date = (datetime.now() - timedelta(seconds=start_time_s)).strftime('%Y-%m-%dT%H:%M:%S')
    if not end_time_s:
        end_date = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    else:
        end_date = (datetime.now() - timedelta(seconds=end_time_s)).strftime('%Y-%m-%dT%H:%M:%S')

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
                metrics = cve['cve']['metrics']
                try:
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss = metrics['cvssMetricV31'][0]
                        cve_data['CVSS_Score'] = cvss.get('cvssData', {}).get('baseScore')
                        cve_data['Severity'] = cvss.get('cvssData', {}).get('baseSeverity')
                        cve_data['CVSS_Version'] = '3.1'
                        cve_data['Exploitablity_Score'] = cvss.get('exploitabilityScore')
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss = metrics['cvssMetricV30'][0]
                        cve_data['CVSS_Score'] = cvss.get('cvssData', {}).get('baseScore')
                        cve_data['Severity'] = cvss.get('cvssData', {}).get('baseSeverity')
                        cve_data['CVSS_Version'] = '3.0'
                        cve_data['Exploitablity_Score'] = cvss.get('exploitabilityScore')
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss = metrics['cvssMetricV2'][0]
                        cve_data['CVSS_Score'] = cvss.get('cvssData', {}).get('baseScore')
                        cve_data['Severity'] = cvss.get('cvssData', {}).get('severity')
                        cve_data['CVSS_Version'] = '2.0'
                        cve_data['Exploitablity_Score'] = cvss.get('exploitabilityScore')
                except (KeyError, IndexError, TypeError) as e:
                    print(f"Error extracting CVSS data for CVE {cve_data['CVE_ID']}: {e}")
            data.append(cve_data)
    else:
        print(f'Error: {res.status_code}')
    
    df = pd.DataFrame(data)
 
    return df


if __name__ == '__main__':
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print('Usage: python cve_matching.py <engine time> <option> <vendor name> ')
        print('option types:  \n',\
            '<none> - take vendor name as is\n',\
            "'-t' - translate vendor name via translation.csv file\n"\
            "'-a' - run for all vendors in translation file")        
        sys.exit(1)
    
    engine_time = int(float(sys.argv[1]))

    #Runs for vendor name translated to searchable name in translation file
    if sys.argv[2] == '-t' and len(sys.argv) == 4:
        with open('translation.csv', 'r') as translator:
            vendor_name = sys.argv[3]
            df = pd.read_csv(translator)
            for i, vendor in enumerate(df['Vendor']):
                if vendor == vendor_name:
                     fetch_CVEs(df['translation'][i], engine_time)
                     break

    #Runs for all vendors present in translation file
    elif sys.argv[2] == '-a' and len(sys.argv) == 3:
        with open('translation.csv', 'r') as translator:
            df = pd.read_csv(translator)
            for row in df['translation']:
                        fetch_CVEs(row, engine_time)

    #Takes vendor name and runs as is
    elif len(sys.argv) == 3:
        vendor = sys.argv[2]
        fetch_CVEs(vendor, engine_time)
       