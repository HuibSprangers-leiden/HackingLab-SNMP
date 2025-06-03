from multiprocessing import Pipe
import subprocess, sys, os
import threading
import signal
import time
import datetime
import socket
import csv
import traceback
import pandas as pd
import numpy as np
from ipwhois import IPWhois
from tqdm import tqdm
import re

ZMAP_END = False
ZMAP_FOLDER = './zmap_outputs/'
TSHARK_FOLDER = './tshark_outputs/'
PARSED_OUTPUTS_FOLDER = './parsed_outputs/'

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def tshark_sniff():
    global ZMAP_END

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
        with open(f"{TSHARK_FOLDER}tshark_output_{timeStamp}.csv", "w") as csvfile:
            writer = csv.writer(csvfile, delimiter=';')
            for line in lines:
                row = line.strip().split(';')
                writer.writerow(row)

        print("TShark capture ended. Saved to "  + f"tshark_output_{timeStamp}.csv. This can now be parsed.")

    except Exception as e:
        print(f"Error during TShark sniffing: {e}")
        print(traceback.format_exc())

def get_enterprise_codes_df():
    # This file contains mappings from enterprise codes to vendor names
    iana_file = "enterprise-numbers.txt"
    with open(iana_file, 'r', encoding='utf-8') as file:
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

def parse_tshark_from_file(file_name, save_to_file):
    try:
        with open(file_name, "r") as f:
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
            # Check if file has timestamp and reuse it for consistency
            timestamp_match = re.search(r'(\d{2}_\d{2}_\d{2}_\d{2}_\d{2})', file_name)
            if timestamp_match:
                timestamp = timestamp_match.group(1)
            else:
                cur_time = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
                timestamp = str.format("{:02d}_{:02d}_{:02d}_{:02d}_{:02d}",cur_time.month, cur_time.day, cur_time.hour, cur_time.minute, cur_time.second)

            # Save file
            df_merged.columns = ['IP','EngineID','Engine Boots', 'Engine Time', 'Enterprise Code', 'MAC', 'Vendor']
            output_file = f'{PARSED_OUTPUTS_FOLDER}parsed_output_{timestamp}.csv'
            df_merged.to_csv(output_file, index=False)
            print(f"Parsed succesfully to: {PARSED_OUTPUTS_FOLDER}parsed_output_{timestamp}.csv")

    except Exception as e:
        print(f"Failed to parse CSV {file_name}: {e}")
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
    

def zmap_scan(ip_list):
    global ZMAP_END

    cur_time = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
    timestamp = str(cur_time.day)+str(cur_time.month)+str(cur_time.hour)+str(cur_time.minute)
    output_filename = f"zmap_ipv4_snmpv3_{timestamp}.csv" 

    command = f"sudo zmap -M udp -p 161 -B 10M --probe-args=file:./snmp3_161.pkt -O csv -f \"*\" -o {ZMAP_FOLDER}{output_filename} -c 10 -w {ip_list} --output-filter=\"success=1 && repeat=0\""
    try:
        print("ZMap scan started...")
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("ZMap scan completed.")
    except subprocess.CalledProcessError as e:
        print("Error during ZMap scan:")
        print(e.stderr)
    finally:
        ZMAP_END = True

def parse_zmap_results(timestamp):
    df = pd.read_csv(f'{ZMAP_FOLDER}zmap_ipv4_snmpv3_{timestamp}.csv')

    # Add a new column for ASN/description
    asn_numbers = []
    asn_descs = []
    asn_country = []
    asn_date = []
    cidr_blocks = []
    net_name = []
    net_type = []

    for ip in tqdm(df['saddr']):
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap()
            asn_numbers.append(res.get('asn'))
            asn_descs.append(res.get('asn_description'))
            asn_country.append(res.get('asn_country_code'))
            asn_date.append(res.get('asn_date'))

            network = res.get('network', {})
            cidr_blocks.append(network.get('cidr'))
            net_name.append(network.get('name'))
            net_type.append(network.get('type'))

        except Exception:
            asn_numbers.append(None)
            asn_descs.append(None)
            asn_country.append(None)
            asn_date.append(None)
            cidr_blocks.append(None)
            net_name.append(None)
            net_type.append(None)

    df['asn'] = asn_numbers
    df['asn_description'] = asn_descs
    df['asn_country'] = asn_country
    df['asn_date'] = asn_date
    df['cidr'] = cidr_blocks
    df['net_name'] = net_name
    df['net_type'] = net_type

    # Save enriched file
    df.to_csv(f'{ZMAP_FOLDER}zmap_enriched_snmp_ips_{timestamp}.csv', index=False)

def enterprise_count(folder_name):
    # This file contains mappings from enterprise codes to vendor names
    iana_file = "enterprise-numbers.txt"
    # file that contains vendors that we exclude, i.e. due to not being middleware
    excluded_vendors = "excluded_vendors.txt"

    with open(iana_file, 'r', encoding='utf-8') as file:
        lines = [line.rstrip('\n') for line in file if line.strip()]

    with open(excluded_vendors, 'r', encoding='utf-8') as file:
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
    df_combined = pd.DataFrame(columns=['IP', 'Enterprise Code', 'MAC', 'Vendor'])

    results_dir = "results"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    # loop over all the csv files 
    for filename in os.listdir(folder_name):
        if filename.endswith(".csv"):
            input_file = os.path.join(folder_name, filename)
            
            df_input = pd.read_csv(input_file)
            df_input.columns = df_input.columns.str.strip()
            df_iana.columns = df_iana.columns.str.strip()

            df_input['Enterprise Code'] = df_input['Enterprise Code'].astype(str)

            df_input = df_input[df_input['Enterprise Code'].notna() & (df_input['Enterprise Code'] != '')]
            df_iana = df_iana[df_iana['Enterprise Code'].notna() & (df_iana['Enterprise Code'] != '')]

            # merge the data
            df_merged = pd.merge(df_input, df_iana, on='Enterprise Code', how='left')

            if 'Vendor_x' in df_merged.columns:
                vendor_column = 'Vendor_x'
            else:
                vendor_column = 'Vendor_y'

            df_output = df_merged[['IP', 'Enterprise Code', 'MAC', vendor_column]]
            df_output.columns = ['IP', 'Enterprise Code', 'MAC', 'Vendor']
            
            df_combined = pd.concat([df_combined, df_output], ignore_index=True)

            print(f"Processed {filename}")

    # output the files to the 'results' folder
    combined_output_file = os.path.join(results_dir, "combined_enterprise_output.csv")
    vendor_count_file = os.path.join(results_dir, "vendor_counts_combined.csv")

    # combine csv, filter out duplicates
    size_before = df_combined.shape[0]
    df_combined.drop_duplicates(inplace=True)
    print("\nDropped " + str(size_before - df_combined.shape[0]) + " duplicates")

    # filter out excluded vendors
    size_before = df_combined.shape[0]
    df_combined = df_combined[~df_combined["Vendor"].isin(excluded_vendors)]
    print("Dropped " + str(size_before - df_combined.shape[0]) + " excluded vendors")

    df_combined.to_csv(combined_output_file, index=False)
    print(f"Combined output written to:          {combined_output_file}")

    # count vendors
    vendor_counts = df_combined['Vendor'].value_counts().reset_index()
    vendor_counts.columns = ['Vendor', 'Count']
    vendor_counts.to_csv(vendor_count_file, index=False)
    print(f"Filtered vendor counts written to:   {vendor_count_file}")

def main():
    # check if valid command line input
    if len(sys.argv) != 3:
        print("Wrong number of args, usage:\n"
              "  python3 script.py scan <path_to_ip_list>\n"
              "  python3 script.py parse <file_name>\n"
              "  python3 script.py enterprise_count <folder_name>\n")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "scan":
        ip_list = sys.argv[2]

        sniff_thread = threading.Thread(target=tshark_sniff)
        zmap_thread = threading.Thread(target=zmap_scan, args=(ip_list,))

        sniff_thread.start()
        time.sleep(1) # Wait for tshark to start capturing
        zmap_thread.start()

        zmap_thread.join()
        sniff_thread.join()

    elif mode == "parse":
        file_name = sys.argv[2]

        parse_tshark_from_file(file_name, True)

    elif mode == "enterprise_count":
        folder_name = sys.argv[2]

        enterprise_count(folder_name)

    elif mode == "zmap_parse":
        timestamp = sys.argv[2]

        parse_zmap_results(timestamp)

    else:
        print("Mode not found, usage:\n"
            "  python3 script.py scan <path_to_ip_list>\n"
            "  python3 script.py parse <file_name>\n"
            "  python3 script.py enterprise_count <folder_name>\n")
        sys.exit(1)

if __name__ == "__main__":
    main()