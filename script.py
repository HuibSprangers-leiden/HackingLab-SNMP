from multiprocessing import Pipe
import subprocess, sys, os
import threading
import signal
import time
import datetime
import socket
import csv

import pandas as pd
from requests import head
from ipwhois import IPWhois
from tqdm import tqdm

ZMAP_END = False

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def tshark_sniff():
    global ZMAP_END

    my_ip = get_ip_address()
    print(my_ip)
    cmd = [
        'sudo', 'tshark',
        #'-i', 'eth0',
        #'-Y', f'snmp && ip.src != {my_ip}',
        '-f', f'udp port 161 and not src host {my_ip}',
        #'-w', 'out.pcap',
        #'-F', 'pcap'
        '-T', 'fields',
        '-e', 'ip.src_host',
        '-e', 'snmp.msgAuthoritativeEngineID',
        #'-e', 'snmp.engineid.conform',
        #'-e', 'snmp.engineid.enterprise',
        #'-e', 'snmp.engineid.format',
        #'-e', 'snmp.engineid.data',
        #'-e', 'snmp.engineid.time',
        '-e', 'snmp.msgAuthoritativeEngineBoots',
        '-e', 'snmp.msgAuthoritativeEngineTime',
        '-E', 'separator=;',
        '-E', 'header=y'
    ]

    print(str.join(" ", cmd))
    try:
        f = open("scan_results.txt", "w")
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
            #print(ZMAP_END)
            if ZMAP_END:
                print(" Stopping TShark...")
                os.killpg(os.getpgid(process.pid), signal.SIGINT)
                lines = process.stdout.readlines()
                break
        
        parse_tshark_out(lines, save_to_file=True)

        print("TShark capture ended.")
    except Exception as e:
        print(f"Error during TShark sniffing: {e}")


def parse_tshark_out(lines, save_to_file=False):
    # First two lines is tshark logs
    lines = lines[2:]
    
    header = lines[0].split(";")
    header[-1] = header[-1].strip('\n')
    lines_with_mac = []

    for line in lines[1:]:
        split_line = line.split(";")
        if len(split_line) == 4:
            ip, id, boots, time = split_line
            time = time.strip('\n')
            mac = extract_mac_from_id(id)
            # TODO: map this mac to a vendor with mac-vendor-lookup

            lines_with_mac.append([ip, id, boots, time, mac])
        else: print(line)
    if save_to_file:
        curTime = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
        timeStamp = str(curTime.day)+str(curTime.hour)+str(curTime.minute)+str(curTime.second)

        with open(f'parsed_output_{timeStamp}.csv', 'w') as f:
            write = csv.writer(f)
            write.writerow(header)
            write.writerows(lines_with_mac)



def extract_mac_from_id(engine_id: str):
    if len(engine_id) < 5:
        return "invalid"
    if "1f88" in engine_id:
        return "net-snmp"
    
    # From: https://www.cisco.com/c/en/us/td/docs/switches/lan/csb_switching_general/olh/Sx300/1-3-0/en/snmp_engine_id.html#:~:text=The%20default%20SNMP%20Engine%20ID,have%20the%20same%20engine%20ID
    # First 4 octets—First bit = 1, the rest is the IANA enterprise number. -> 0x8000
    # Fifth octet—Set to 3 to indicate the MAC address that follows. 
    # Last 6 octets—MAC address of the device.
    if engine_id[0] != '8':
        return "malformed_id"

    if engine_id[4] != '3':
        return "no_mac_indication"
    
    return engine_id[5:]


def zmap_scan():
    global ZMAP_END
    #command = "sudo zmap -M udp -p 161 -B 10M --probe-args=file:snmp3_161.pkt 5.45.67.59"

    curTime = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = str(curTime.day)+str(curTime.hour)+str(curTime.minute)+str(curTime.second)

    command = "sudo zmap -M udp -p 161 -B 10M --probe-args=file:./snmp3_161.pkt -O csv -f \"*\" -o zmap_ipv4_snmpv3_"+timeStamp+".csv -c 10 -w ./ip_whitelist --output-filter=\"success=1 && repeat=0\""
    try:
        print("ZMap scan started...")
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("ZMap scan completed.")
    except subprocess.CalledProcessError as e:
        print("Error during ZMap scan:")
        print(e.stderr)
    finally:
        ZMAP_END = True


def parse_zmap_results():
    curTime = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
    timeStamp = str(curTime.day)+str(curTime.hour)+str(curTime.minute)+str(curTime.second)
    df = pd.read_csv('zmap_ipv4_snmpv3_'+timeStamp+'.csv')

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
    df.to_csv('zmap_enriched_snmp_ips_'+timeStamp+'.csv', index=False)


sniff_thread = threading.Thread(target=tshark_sniff)
zmap_thread = threading.Thread(target=zmap_scan)

sniff_thread.start()
time.sleep(1) # Wati for tshark to start capturing
zmap_thread.start()

zmap_thread.join()
sniff_thread.join()