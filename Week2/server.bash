#!/bin/bash

# Script to create Wireguard server

# Check for existing config/if we want to override
if [[ -f "wg0.conf" ]]
then
	# Prompt if overwrite
	echo "The file wg0.conf already exists."
	echo -n "Do you want to overwrite it? [y|N]"
	read overwrite
	if [[ "${overwrite}" == "N" || "${overwrite}" == "" || "${overwrite}" == "n" ]]
	then
		echo "Exiting.."
		exit 0
	elif [[ "${overwrite}" == "y" ]]
	then
		echo "Creating the Wireguard config file.."
	# If y/N not specified, error
	else
		echo "Invalid entry"
		exit 1
	fi
fi

# Create private key
p="$(wg genkey)"

# Create public key
pub="$(echo ${p} | wg pubkey)"

# Set the addresses
address="10.254.132.0/24,172.16.28.0/24"

# Set server IP addresses
ServerAddress="10.254.132.1/24,172.16.28.1/24"

# Set listening port
lport="4282"

#Create format for client config
peerInfo="# ${address} 192.199.97.163:4282 ${pub} 8.8.8.8,1.1.1.1 1280 120 0.0.0.0/0"

echo "${peerInfo}
[Interface]
Address=${ServerAddress}
#PostUp=/etc/wireguard/wg-up.bash
#PostDown=/etc/wireguard/wg-down.bash
ListenPort=${lport}
PrivateKey=${p}
" > wg0.conf
