#!/bin/bash

# Create peer VPN config file

# What is user/peer name?
echo -n "What is the peer's name?"
read client

# Filename var
pFile="${client}-wg0.conf"

# Check for pre-existing config file/if we want to override
if [[ -f "${pFile}" ]]
then
	# Prompt if file needs to be overwritten
	echo "The file ${pFile} already exists."
	echo -n "Do you want to overwrite it? [y|N]"
	read to_overwrite
	
	if [[ "${to_overwrite}" == "N" || "${to_overwrite}" == "" || "${to_overwrite}" == "n" ]]
	then
		echo "Exiting.."
		exit 0
	elif [[ "${to_overwrite}" == "y" ]]
	then
		echo "Creating the Wireguard config file.."
	# If y/N isn't specified, error
	else
		echo "Invalid entry"
		exit 1
	fi
fi

#Generate private key
p="$(wg genkey)"

# Generate public key
clientPub="$(echo ${p} | wg pubkey)"

# Generate preshared key
pre="$(wg genpsk)"

# Endpoint
end="$(head -1 wg0.conf | awk ' { print $3 } ')"

# Server public key
pub="$(head -1 wg0.conf | awk ' { print $4 } ')"

# DNS servers
dns="$(head -1 wg0.conf | awk ' { print $5 } ')"

# MTU
mtu="$(head -1 wg0.conf | awk ' { print $6 } ')"

# KeepAlive
keep="$(head -1 wg0.conf | awk ' { print $7 } ')"

# Listening port
lport="$(shuf -n1 -i 40000-50000)"

# Default VPN routes
routes="$(head -1 wg0.conf | awk ' { print $8} ')"

# Create client config file
echo "[Interface]
Address = 10.254.132.100/24
DNS = ${dns}
ListenPort = ${lport}
MTU = ${mtu}
PrivateKey = ${p}
[Peer]
AllowedIPs = ${routes}
PersistentKeepAlive = ${keep}
PresharedKey = ${pre}
PublicKey = ${pub}
Endpoint = ${end}
" > ${pFile}

# Add peer config to server config
echo "
# ${client} begin
[Peer]
PublicKey = ${clientPub}
PresharedKey = ${pre}
AllowedIPs = 10.254.132.100/32
# ${client} end" | tee -a wg0.conf

echo "
sudo cp wg0.conf /etc/wireguard
sudo wg addconf wg0 <(wg-quick strip wg0)
" 
