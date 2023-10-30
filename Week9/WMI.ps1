# Use the Get-WMIobject cmdlet
# Get-WmiObject -Class Win32_service | Select Name, PathName, ProcessId
# Get-WmiObject -List | where { $_.Name -ilike "Win32_[n-z]*" } | sort-object
# Get-WmiObject -Class Win32_Account | get-member

# Task: Grab the network adapter information using the WMI class
Get-WmiObject -Class Win32_NetworkAdapter

# Get the IP address, default gateway, DNS servers, and the DHCP servers
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object IPAddress, DefaultIPGateway, DNSDomain, DHCPServer