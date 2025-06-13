import csv
import datetime
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback

import numpy as np
import pandas as pd
from ipwhois import IPWhois

ZMAP_END = False
ZMAP_FOLDER = './outputs/zmap/'
TSHARK_FOLDER = './outputs/tshark/'
PARSED_OUTPUTS_FOLDER = './outputs/parsed/'
RESULTS_OUTPUT_FOLDER = './outputs/results/'
IANA_FILE = "config/enterprise-numbers.txt"
EXCLUDED_VENDORS = "config/excluded_vendors.txt"

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def tshark_sniff(ip_list_path):
    global ZMAP_END

    ip_file_name = get_file_name(ip_list_path)

    my_ip = get_ip_address()
    cmd = [
        'sudo', 'tshark',
        '-f', f'udp port 161 and not src host {my_ip}',
        '-T', 'fields',
        '-e', 'ip.src_host',
        '-e', 'snmp.msgAuthoritativeEngineID',
        '-e', 'snmp.msgAuthoritativeEngineBoots',
        '-e', 'snmp.msgAuthoritativeEngineTime',
        '-E', 'separator=;',
        '-E', 'header=y'
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid
        )
        lines = []
        print("TShark started...")
        while True:
            if ZMAP_END:
                print(" Stopping TShark...")
                os.killpg(os.getpgid(process.pid), signal.SIGINT)
                lines = process.stdout.readlines()
                break

        curTime = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
        timeStamp = str.format("{:02d}_{:02d}_{:02d}_{:02d}_{:02d}",curTime.month, curTime.day, curTime.hour, curTime.minute, curTime.second)

        # save to csv, so we can parse afterwards in case of unexpected errors
        with open(f"{TSHARK_FOLDER}tshark_{ip_file_name}_output_{timeStamp}.csv", "w") as csvfile:
            writer = csv.writer(csvfile, delimiter=';')
            for line in lines:
                row = line.strip().split(';')
                writer.writerow(row)

        print("TShark capture ended. Saved to "  + f"tshark_{ip_file_name}_output_{timeStamp}.csv. This can now be parsed.")

    except Exception as e:
        print(f"Error during TShark sniffing: {e}")
        print(traceback.format_exc())

def get_enterprise_codes_df():
    with open(IANA_FILE, 'r', encoding='utf-8') as file:
        lines = [line.rstrip('\n') for line in file if line.strip()]

    iana_data = []
    i = 0
    while i < len(lines):
        if lines[i].isdigit():
            try:
                code = lines[i].strip()
                vendor = lines[i+1].strip()
                iana_data.append({
                    'Enterprise code': code,
                    'Vendor': vendor
                })
                i += 4  # Skip ahead to the next entry
            except IndexError:
                break
        else:
            i += 1

    df_iana = pd.DataFrame(iana_data)
    df_iana = df_iana[df_iana['Enterprise code'].apply(lambda x: x.isnumeric())]
    df_iana['Enterprise code'] = df_iana['Enterprise code'].astype(np.int64)

    return df_iana

def parse_tshark_from_file(file_path, save_to_file):
    try:
        with open(file_path, "r") as f:
            reader = csv.reader(f, delimiter=';')
            lines = list(reader)
            start = 0
            for i, line in enumerate(lines):
                if "ip.src_host" in line:
                    start = i
                    break
        
        lines = lines[start:] # just skip the first lines as this is how many packets we captured etc

        # Remove tshark logs
        header = lines[0]
        header.append("Enterprise code")
        header.append("Mac")

        lines_with_mac = []
        
        # Add iana enterprise code and mac
        for row in lines[1:]:
            if len(row) == 4:
                ip, id, boots, time = row
                iana, mac = extract_iana_and_mac_from_id(id)
                lines_with_mac.append([ip, id, boots, time, iana, mac])
            else:
                print("Invalid row:", row)

        # Map enterprise code to vendor 
        df_iana = get_enterprise_codes_df()
        df_data = pd.DataFrame(lines_with_mac, columns=header)
        df_data['Enterprise code'] = pd.to_numeric(df_data['Enterprise code'], errors='coerce')
        df_merged = pd.merge(df_data, df_iana, on='Enterprise code', how='left')


        if save_to_file:
            # extract the ip file name
            ip_file_name_pattern = r'(?<=tshark_)(.*?)(?=_output)'
            ip_file_name_match = re.search(ip_file_name_pattern, file_path)

            if ip_file_name_match:
                ip_file_name = ip_file_name_match.group()
            else:
                # raise error as this should match
                raise ValueError(f"Ip file not found in file name: {file_path}. The file name should contain an time stamp.")

                
            # Check if file has timestamp and reuse it for consistency
            timestamp_match = re.search(r'(\d{2}_\d{2}_\d{2}_\d{2}_\d{2})', file_path)
            if timestamp_match:
                timestamp = timestamp_match.group(1)
            else:
                # raise error as this should match
                raise ValueError(f"Timestamp not found in file name: {file_path}. The file name should contain an time stamp.")

            # Save file
            df_merged.columns = ['IP','EngineID','Engine Boots', 'Engine Time', 'Enterprise Code', 'MAC', 'Vendor']
            output_file = f'{PARSED_OUTPUTS_FOLDER}parsed_{ip_file_name}_output_{timestamp}.csv'
            df_merged.to_csv(output_file, index=False)
            print(f"Parsed succesfully to: {PARSED_OUTPUTS_FOLDER}parsed_{ip_file_name}_output_{timestamp}.csv")

    except Exception as e:
        print(f"Failed to parse CSV {file_path}: {e}")
        print(traceback.format_exc())

    
def extract_iana_and_mac_from_id(engine_id_str: str):
    try:
        engine_id = bytes.fromhex(engine_id_str)
    except Exception as e:
        return ("invalid", "invalid")
    if len(engine_id) <= 5:
        return ("invalid", "invalid")
    
    enterprise_code = "not_set"
    mac = "not_set"

    # Engine ID parsing method is based on: https://www.rfc-editor.org/rfc/pdfrfc/rfc3411.txt.pdf page 42

    # If first bit -> 1 means SNMPv3 format, else older format is used
    if engine_id[0] & 0x80 == 0x80: 
        enterprise_bytes = engine_id[:4] 
        # Set the first bit of the first byte to zero (to extract the IANA number)
        enterprise_bytes = bytes([enterprise_bytes[0] & 0x7F]) + enterprise_bytes[1:]
        enterprise_code = str(int.from_bytes(enterprise_bytes, byteorder='big'))
        
        # Check for mac indication on 5th octet
        if engine_id[4] == 0x03:
            mac = engine_id[5:].hex() # TODO: This might contain padding, find a way to remove it
        else:
            mac = "No Mac indication (0x03)"
    else:
        enterprise_bytes = engine_id[:4]
        enterprise_code = str(int.from_bytes(enterprise_bytes, byteorder='big'))

    return (enterprise_code, mac)
    

def zmap_scan(ip_list_path):
    global ZMAP_END

    ip_file_name = get_file_name(ip_list_path)

    cur_time = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
    timestamp = str(cur_time.day)+str(cur_time.month)+str(cur_time.hour)+str(cur_time.minute)
    output_filename = f"zmap_{ip_file_name}_snmpv3_{timestamp}.csv" 

    command = f"sudo zmap -M udp -p 161 -B 10M --probe-args=file:./config/snmp3_161.pkt -O csv -f \"*\" -o {ZMAP_FOLDER}{output_filename} -c 10 -w {ip_list_path} --output-filter=\"success=1 && repeat=0\""
    try:
        print("ZMap scan started...")
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("ZMap scan completed.")
    except subprocess.CalledProcessError as e:
        print("Error during ZMap scan:")
        print(e.stderr)
    finally:
        ZMAP_END = True

def parse_zmap_results(input_file):
    df = pd.read_csv(input_file)

    asn_numbers = []
    asn_country = []
    asn_date = []
    cidr_blocks = []

    asns = {}

    for _, row in df.iterrows():
        try:
            obj = IPWhois(row['IP'])  # replace 'IP' with the actual column name of IP addresses in your CSV
            res = obj.lookup_rdap()

            asn_num = res.get('asn')
            asns[asn_num] = asns.get(asn_num, 0) + 1
            asn_numbers.append(asn_num)

            asn_country.append(res.get('asn_country_code'))
            asn_date.append(res.get('asn_date'))

            network = res.get('network', {})
            cidr_blocks.append(network.get('cidr'))

        except Exception as e:
            asn_country.append(None)
            asn_date.append(None)
            cidr_blocks.append(None)
            asn_numbers.append(None)

    enriched_df = pd.DataFrame({
        'IP': df['IP'],
        'asn_num': asn_numbers,
        'asn_country': asn_country,
        'asn_date': asn_date,
        'cidr': cidr_blocks,
    })

    # Save to a different CSV file using the current timestamp
    cur_time = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
    timestamp = str.format("{:02d}_{:02d}_{:02d}_{:02d}_{:02d}", cur_time.month, cur_time.day, cur_time.hour,
                           cur_time.minute, cur_time.second)

    enriched_df.to_csv(f'{ZMAP_FOLDER}zmap_enrichment_only_{timestamp}.csv', index=False)
    print(asns)     # Shows AS numbers and their count

def enterprise_count(folder_name, reboot_threshold):
    with open(IANA_FILE, 'r', encoding='utf-8') as file:
        lines = [line.rstrip('\n') for line in file if line.strip()]

    with open(EXCLUDED_VENDORS, 'r', encoding='utf-8') as file:
        excluded_vendors = {line.strip() for line in file if line.strip()}

    iana_data = []
    i = 0
    while i < len(lines):
        if lines[i].isdigit():
            try:
                code = lines[i].strip()
                vendor = lines[i+1].strip()
                iana_data.append({
                    'Enterprise Code': code,
                    'Vendor': vendor
                })
                i += 4  # Skip ahead to the next entry
            except IndexError:
                break
        else:
            i += 1

    df_iana = pd.DataFrame(iana_data)
    df_iana['Enterprise Code'] = df_iana['Enterprise Code'].astype(str)

    # Create an empty DataFrame to store the combined data
    df_combined = pd.DataFrame(columns=['IP', 'Enterprise Code', 'MAC', 'Engine Time', 'Engine Boots', 'Vendor'])

    if not os.path.exists(RESULTS_OUTPUT_FOLDER):
        os.makedirs(RESULTS_OUTPUT_FOLDER)

    processed_ips = {}

    # loop over all the csv files
    for filename in os.listdir(folder_name):
        if filename.endswith(".csv"):
            input_file = os.path.join(folder_name, filename)

            # get scan date from this file name
            timestamp_match = re.search(r'(\d{2}_\d{2}_\d{2}_\d{2}_\d{2})', filename)
            if timestamp_match:
                scan_date = timestamp_match.group(1)
            else:
                # raise error as this should match
                raise ValueError(f"Timestamp not found in file name: {filename}. The file name should contain an time stamp.")

            df_input = pd.read_csv(input_file)
            df_input.columns = df_input.columns.str.strip()
            df_iana.columns = df_iana.columns.str.strip()

            df_input['Enterprise Code'] = df_input['Enterprise Code'].astype(str)

            df_input = df_input[df_input['Enterprise Code'].notna() & (df_input['Enterprise Code'] != '') & df_input['Engine Time'] > 0]
            df_iana = df_iana[df_iana['Enterprise Code'].notna() & (df_iana['Enterprise Code'] != '')]

            # merge the data
            df_merged = pd.merge(df_input, df_iana, on='Enterprise Code', how='left')

            # if no vendor, we categorise as 'unknown'
            df_merged['Vendor_x'] = df_merged['Vendor_x'].fillna('unknown')
            
            # Set vendor to 'Arista networks' if engineID starts with f5717f
            # https://avd.sh/en/v3.8.6/roles/eos_designs/doc/management-settings.html
            df_merged.loc[(df_merged['Vendor_x'] == 'unknown') & (df_merged['EngineID'].str.startswith('f5717f', na=False)), 'Vendor_x'] = 'Arista networks'

            df_merged['Scan Date'] = scan_date
            df_merged['Reboot Date'] = df_merged['Engine Time'].apply(lambda x: engine_time_to_date(int(x), datetime.datetime.strptime(scan_date, '%m_%d_%H_%M_%S')))

            # go through the merged df and update df_combined
            for index, row in df_merged.iterrows():
                ip = row['IP']
                reboot_date = row['Reboot Date']
                scan_date = row['Scan Date']

                # Ccheck if ip already exists
                if ip in df_combined['IP'].values:
                    # find this row, then check to delete and just add the new row
                    existing_row = df_combined[df_combined['IP'] == ip]
                    existing_reboot_date = existing_row['Reboot Date'].values[0]

                    # delete if difference is more than a day
                    if datetime.datetime.strptime(reboot_date, '%m_%d_%Y_%H_%M_%S') > datetime.datetime.strptime(existing_reboot_date, '%m_%d_%Y_%H_%M_%S') + datetime.timedelta(seconds=86400):
                        row_index = df_combined[df_combined['IP'] == ip].index
                        df_combined = df_combined.drop(row_index)
                        print("MORE UP TO DATE, old: " + existing_reboot_date + ", new: " + reboot_date)

            df_output = df_merged[['IP', 'Enterprise Code', 'MAC', 'Engine Time', 'Engine Boots', 'Vendor_x', 'Scan Date', 'Reboot Date']]
            df_output.columns = ['IP', 'Enterprise Code', 'MAC', 'Engine Time', 'Engine Boots', 'Vendor', 'Scan Date', 'Reboot Date']
            
            df_combined = pd.concat([df_combined, df_output], ignore_index=True)

            print(f"Processed {filename}")

    # output the files to the 'results' folder
    combined_output_file = os.path.join(RESULTS_OUTPUT_FOLDER, "combined_enterprise_output.csv")
    combined_output_file_timed = os.path.join(RESULTS_OUTPUT_FOLDER, "combined_enterprise_output_timed.csv")
    vendor_count_file = os.path.join(RESULTS_OUTPUT_FOLDER, "vendor_counts_combined.csv")
    vendor_count_file_timed = os.path.join(RESULTS_OUTPUT_FOLDER, "vendor_counts_combined_timed.csv")

    # combine csv, filter out duplicates
    size_before = df_combined.shape[0]
    df_combined.drop_duplicates(subset=['IP'], inplace=True)
    print("\nDropped " + str(size_before - df_combined.shape[0]) + " duplicates.")

    # filter out excluded vendors
    size_before = df_combined.shape[0]
    df_combined = df_combined[~df_combined["Vendor"].isin(excluded_vendors)]
    print("Dropped " + str(size_before - df_combined.shape[0]) + " by vendor exclusion.\n" + str(df_combined.shape[0]) + " entries left.")

    df_combined.to_csv(combined_output_file, index=False)
    print(f"Combined output written to:          {combined_output_file}")

    # count vendors
    vendor_counts = df_combined['Vendor'].value_counts().reset_index()
    vendor_counts.columns = ['Vendor', 'Count']
    vendor_counts.to_csv(vendor_count_file, index=False)
    print(f"Filtered vendor counts written to:   {vendor_count_file}")

    # filter on engine time in seconds
    size_before = df_combined.shape[0]
    df_combined['Engine Time'] = pd.to_numeric(df_combined['Engine Time'])
    df_combined = df_combined[df_combined['Engine Time'] >= reboot_threshold]
    print("\nDropped " + str(size_before - df_combined.shape[0]) + " entries based on engine time of " + str(size_before) + " total. \n" + str(df_combined.shape[0]) + " entries left.")
    df_combined.to_csv(combined_output_file_timed, index=False)
    print(f"Combined output written to:          {combined_output_file_timed}")

    # count vendors after this engine filter
    vendor_counts1 = df_combined['Vendor'].value_counts().reset_index()
    vendor_counts1.columns = ['Vendor', 'Count']
    vendor_counts1.to_csv(vendor_count_file_timed, index=False)
    print(f"Filtered vendor counts written to:   {vendor_count_file_timed}")

def engine_time_to_date(engine_time, scan_date):
    if isinstance(scan_date, str):
        scan_date = datetime.datetime.strptime(scan_date, '%m_%d_%H_%M_%S')

    scan_date = scan_date.replace(year=2025)
    reboot_time = scan_date - datetime.timedelta(seconds=engine_time)
    return reboot_time.strftime('%m_%d_%Y_%H_%M_%S')

def date_to_engine_time(reboot_date_str, scan_date):
    reboot_date = datetime.datetime.strptime(reboot_date_str, '%m_%d_%Y_%H_%M_%S')
    time_difference = scan_date - reboot_date

    engine_time = int(time_difference.total_seconds())
    return engine_time

def get_file_name(file_path):
    pattern = r'[\w-]+?(?=\.)'
    return re.search(pattern, file_path).group()

def commandline_help():
    print("Script usage:\n"
            "  python3 script.py scan <path_to_ip_list>\n"
            "  python3 script.py parse <file_name>\n"
            "  python3 script.py enterprise_count <folder_name> reboot_threshold\n"
            "  python3 script.py parse_asn <path_to_ip_list>\n")
    sys.exit(1)

def main():
    mode = sys.argv[1]

    if mode == "scan":
        if len(sys.argv) != 3:
            commandline_help()
        ip_list_path = sys.argv[2]

        sniff_thread = threading.Thread(target=tshark_sniff, args=(ip_list_path,))
        zmap_thread = threading.Thread(target=zmap_scan, args=(ip_list_path,))

        sniff_thread.start()
        time.sleep(1) # Wait for tshark to start capturing
        zmap_thread.start()

        zmap_thread.join()
        sniff_thread.join()

    elif mode == "parse":
        if len(sys.argv) != 3:
            commandline_help()
        file_path = sys.argv[2]

        parse_tshark_from_file(file_path, True)

    elif mode == "enterprise_count":
        if len(sys.argv) != 4:
            commandline_help()
        folder_name      = sys.argv[2]
        reboot_threshold = int(sys.argv[3])

        enterprise_count(folder_name, reboot_threshold)

    elif mode == "parse_asn":
        if len(sys.argv) != 3:
            commandline_help()
        input_file_path = sys.argv[2]
        parse_zmap_results(input_file_path)

    else:
        print("Mode not found.")
        commandline_help()

if __name__ == "__main__":
    main()