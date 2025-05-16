import subprocess, sys, os

command = "sudo zmap -M udp -p 161 -B 10M --probe-args=file:./snmp3_161.pkt -O csv -f \"*\" -o zmap_ipv4_snmpv3.csv -r 30000 -c 10 -w ./ip_whitelist"

os.system(command)