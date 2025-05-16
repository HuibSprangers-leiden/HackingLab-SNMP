#!/bin/bash

sudo zmap -p 161 --probe-args=file:snmp3_161.pkt -O csv -f "*" -o zmap_ipv4_snmpv3.csv -r 30000 -c 10 -w ./ip_whitelist