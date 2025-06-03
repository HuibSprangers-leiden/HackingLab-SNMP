import os
import pandas as pd

MAPPED_FOLDER = './outputs/mapped/'

input_file = "parsed_output_05_27_16_05_46.csv"
df_input = pd.read_csv(input_file)

# This file contains mappings from enterprise codes to vendor names
iana_file = "config/enterprise-numbers.txt"
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

# This joins on the "Enterprise code" column
df_merged = pd.merge(df_input, df_iana, on='Enterprise code', how='left')

df_output = df_merged[['ip.src_host', 'Enterprise code', 'Mac', 'Vendor']]
df_output.columns = ['IP', 'Enterprise Code', 'MAC', 'Vendor']

output_file = os.path.join(MAPPED_FOLDER, "mapped_enterprise_output_2.csv")
df_output.to_csv(output_file, index=False)

print(f"Done. Output written to: {output_file}")

# Count appearances of each vendor
vendor_counts = df_output['Vendor'].value_counts().reset_index()
vendor_counts.columns = ['Vendor', 'Count']

# Save vendor counts to a separate file
vendor_count_file = os.path.join(MAPPED_FOLDER, "vendor_counts_2.csv")
vendor_counts.to_csv(vendor_count_file, index=False)

print(f"Vendor counts written to: {vendor_count_file}")