import datetime
import os

import pandas as pd
from ipwhois import IPWhois
from tqdm import tqdm

curTime = datetime.datetime.strptime(str(datetime.datetime.now()), "%Y-%m-%d %H:%M:%S.%f")
timeStamp = str(curTime.day)+str(curTime.hour)+str(curTime.minute)+str(curTime.second)
command = "sudo zmap -M udp -p 161 -B 10M --probe-args=file:./snmp3_161.pkt -O csv -f \"*\" -o zmap_ipv4_snmpv3_"+timeStamp+".csv -r 30000 -c 10 -w ./ip_whitelist"

os.system(command)

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