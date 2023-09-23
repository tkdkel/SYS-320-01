#!/bin/bash

# Storyline: Extract IPs from emergingthreats.net and create a firewall ruleset

# alert ip [2.57.234.0/23,2.58.148.0/22,5.42.199.0/24,5.134.128.0/19,5.183.60.0/22,5.188.10.0/23,24.137.16.0/20
# ,24.170.208.0/20,24.233.0.0/19,24.236.0.0/19,27.123.208.0/22,27.126.160.0/20,27.146.0.0/16,31.24.81.0/24,31.
# 41.244.0/24,31.217.252.0/24,31.222.236.0/24,36.0.8.0/21,36.37.48.0/20,36.116.0.0/16] any -> $HOME_NET any 
# (msg:"ET DROP Spamhaus DROP Listed Traffic Inbound group 1"; reference:url,www.spamhaus.org/drop/drop.lasso; 
# threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; flowbits:set,ET.Evil; 
# flowbits:set,ET.DROPIP; sid:2400000; rev:3749; metadata:affected_product Any, attack_target Any, deployment 
# Perimeter, tag Dshield, signature_severity Minor, created_at 2010_12_30, updated_at 2023_09_22;)


# Regex to extract the networks
# 2.57.234.0/23

# wget http://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules -o /tmp/emerging-drop.suricata.rules
egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/[0-9]{1,2}' /tmp/emerging-drop.suricata.rules | sort -u | tee badIPs.txt


# Create a firewall ruleset

for eachIP in $(cat badIPs.txt)

do
	echo "iptables -A INPUT -s ${eachIP} -j DROP" | tee -a badIPs.iptables
done
