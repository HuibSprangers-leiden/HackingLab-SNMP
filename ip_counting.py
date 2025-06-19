"""
Counts the total number of IP addresses in a list of CIDR ranges.
"""

import sys

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ip_counting.py <path_to_ip_list>")
        sys.exit(1)

    file = sys.argv[1]

    ip_count = 0

    with open(file, 'r') as ip_list:
        for ip_range in ip_list:
            bits = 32 - int(ip_range.split("/")[1])
            ips = 2**bits
            ip_count += ips

    print(ip_count)

if __name__ == "__main__":
    main()