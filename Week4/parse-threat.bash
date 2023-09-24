#!/bin/bash

# Storyline: Extract IPs from emergingthreats.net and create a firewall ruleset

# alert ip [2.57.234.0/23,2.58.148.0/22,5.42.199.0/24,5.134.128.0/19,5.183.60.0/22,5.188.10.0/23,24.137.16.0/20
# ,24.170.208.0/20,24.233.0.0/19,24.236.0.0/19,27.123.208.0/22,27.126.160.0/20,27.146.0.0/16,31.24.81.0/24,31.
# 41.244.0/24,31.217.252.0/24,31.222.236.0/24,36.0.8.0/21,36.37.48.0/20,36.116.0.0/16] any -> $HOME_NET any 
# (msg:"ET DROP Spamhaus DROP Listed Traffic Inbound group 1"; reference:url,www.spamhaus.org/drop/drop.lasso; 
# threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; flowbits:set,ET.Evil; 
# flowbits:set,ET.DROPIP; sid:2400000; rev:3749; metadata:affected_product Any, attack_target Any, deployment 
# Perimeter, tag Dshield, signature_severity Minor, created_at 2010_12_30, updated_at 2023_09_22;)


# Define the file
et_file="/tmp/emerging-drop.suricata.rules"


# Check for existing emerging threats file and ask if we want to download it again
if [[ -f "${et_file}" ]]
then
	#Prompt if we need to download the file again
	echo "The file ${et_file} already exists."
	echo -n "Do you want to download it again? [y|N]"
	read to_download

	if [[ "${to_download}" == "N" || "${to_download}" == "" || "${to_download}" == "n" ]]
	then
		echo "Using the existing file..."
	elif [[ "${to_download}" == "y" || "${to_download}" == "Y" ]]
	then
		echo "Downloading the emerging threats file..."
		wget http://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules -O "${et_file}"
	else
		echo "Invalid value"
		exit 1
	fi
else
	# Download the file if it doesn't exist
	wget http://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules -O "${et_file}"
fi


# Initialize option variable
opt=""


# Parse firewall options
while getopts "icwmp:" OPTION
do
	case ${OPTION} in
		i)
			opt="iptables"
			;;
		c)
			opt="cisco"
			;;
		w)
			opt="windows"
			;;
		m)
			opt="macos"
			;;
		p)
			opt="parse"
			url_file=$OPTARG
			;;
		*)
			echo "Invalid option"
			exit 1
			;;
	esac
done


# Regex to extract the networks
# wget http://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules -o /tmp/emerging-drop.suricata.rules
# egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/[0-9]{1,2}' /tmp/emerging-drop.suricata.rules | sort -u | tee badIPs.txt


# Based on choice, create firewall rules
if [[ $opt == "parse" ]]
then
	wget https://raw.githubusercontent.com/botherder/targetedthreats/master/targetedthreats.csv -O /tmp/targetedthreats.csv
	temp_url_file="/tmp/targetedthreats.csv"
	echo "class-map match-any BAD_URLS" | tee badURLs.cisco
	curl -s $temp_url_file | grep ",domain," | cut -d',' -f3 | sort -u | while read -r domain
	do
		echo "match protocol http host \"$domain\"" | tee -a badURLs.cisco
	done
else
	egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.0/[0-9]{1,2}' "${et_file}" | sort -u | tee badIPs.txt
	for eachIP in $(cat badIPs.txt)
	do
		case $opt in
			"iptables")
				echo "iptables -A INPUT -s ${eachIP} -j DROP" | tee -a badIPs.iptables
				;;
			"cisco")
				echo "access-list inbound_acl deny ip ${eachIP} any" | tee -a badIPs.cisco
				;;
			"windows")
				echo "netsh advfirewall firewall add rule name=\"Block ${eachIP}\" dir=in action-block remoteip=${eachIP}" | tee -a badIPs.windows
				;;
			"macos")
				echo "sudo pfctl -t blocklist -T add ${eachIP}" | tee -a badIPs.macos
				;;
			*)
				echo "No valid option selected"
				;;
		esac
	done
fi
