#!/bin/bash


# Prompt user to enter the path of an Apache log file
read -p "Please enter the path of an Apache log file: " APACHE_LOG


# Check if the entered path points to a valid file. If not, exit the script.
if [[ ! -f ${APACHE_LOG} ]]; then
    echo "Please specify the path to a valid log file."
    exit 1
fi


# Extract unique IP addresses from the log file and generate commands to block them using netsh and iptables
# match() sets the values of RSTART and RLENGTH which indicate the starting position and length.
# Using regex here is absolutely unnecessary and overengieering this.
awk '{match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); print substr($0, RSTART, RLENGTH)}' "${APACHE_LOG}" | sort -u | while read -r bIP; do
  # Parse through the log file
  if grep -qEi 'test|shell|echo|passwd|select|phpmyadmin|setup|admin|w00t' "${APACHE_LOG}"; then
    # Generate command to block the IP address using netsh and save it to a PowerShell script that can be ran on a windows machine.
    echo "netsh advfirewall firewall add rule add rule name=\"BLOCK IP ADDRESS - ${bIP}\" dir=in action=block remoteip=${bIP}" >> blockedips.ps1
    # Generate command to block the IP address using iptables and save it to an iptables script
    echo "iptables -A INPUT -s ${bIP} -j DROP" >> blockedips.iptables
  fi
done


# Print a finishing message.
echo "Scripts to block IP addresses have been generated and saved to blockedips.ps1 and blockedips.iptables."
