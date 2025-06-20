import pandas as pd
import matplotlib.pyplot as plt

if __name__ == '__main__':
    list_asns = ['33915', '50266', '20559', '1136', '15830', '35055', '54825', '211826', '64437', '16350']
    network_types = ['ISP', 'ISP', 'Hosting', 'ISP', 'Hosting', 'Education' , 'Hosting','Hosting','Hosting','Hosting',]
    # Load CSVs
    df_zmap = pd.read_csv("./outputs/zmap/zmap_enrichment_only_06_10_22_11_37.csv", dtype=str)
    df_enterprise = pd.read_csv("./outputs/results/combined_enterprise_output.csv", dtype=str)

    # Clean column names
    df_zmap.columns = df_zmap.columns.str.strip()
    df_enterprise.columns = df_enterprise.columns.str.strip()

    # Drop rows with missing ASN numbers
    df_zmap = df_zmap.dropna(subset=['asn_num'])

    # Ensure 'asn_num' and 'IP' are treated as strings
    df_zmap['asn_num'] = df_zmap['asn_num'].astype(str)
    df_zmap['IP'] = df_zmap['IP'].astype(str)
    df_enterprise['IP'] = df_enterprise['IP'].astype(str)

    # Convert engine fields to numbers with fallback to 0
    df_enterprise['Engine Time'] = pd.to_numeric(df_enterprise['Engine Time'], errors='coerce').fillna(0).astype(int)
    df_enterprise['Engine Boots'] = pd.to_numeric(df_enterprise['Engine Boots'], errors='coerce').fillna(0).astype(int)

    network_type_data = {}
    # Process each ASN
    for asn in list_asns:
        ips = set(df_zmap[df_zmap['asn_num'] == asn]['IP'])

        print(f"ASN {asn} - Found {len(ips)} IPs")

        filtered = df_enterprise[df_enterprise['IP'].isin(ips)]

        filtered = filtered[filtered['Engine Boots'] <= 10000000]
        filtered = filtered[filtered['Engine Time'] <= 850000000]


        # Get the network type for this ASN
        network_type = network_types[list_asns.index(asn)]

        print(f"Network Type: {network_type}")
        if network_type in network_type_data:
            network_type_data[network_type] = pd.concat([network_type_data[network_type], filtered])
        else:
            network_type_data[network_type] = filtered
        # print(f"ASN: {asn}")
        # print(f"Total IPs matched: {count}")
        # print(f"Average Engine Time: {engineTime}")
        # print(f"Average Engine Boots: {engineBoots}")
        # print("-" * 30)

    # Process each network type's statistics
    for network_type, data in network_type_data.items():
        avg_engine_time = data['Engine Time'].mean()
        avg_engine_boots = data['Engine Boots'].mean()
        count = len(data)
        print(f"\nNetwork Type: {network_type}")
        print(f"Count: {count}")
        print(f"Average Engine Time: {avg_engine_time:.2f}")
        print(f"Average Engine Boots: {avg_engine_boots:.2f}")

# Create data for pie chart
ip_counts = {network_type: len(data) for network_type, data in network_type_data.items()}

# Plot pie chart

plt.figure(figsize=(10, 8))
plt.pie(ip_counts.values(), labels=ip_counts.keys(), autopct='%1.1f%%')
plt.title('Distribution of IPs by Network Type')
plt.axis('equal')
plt.show()