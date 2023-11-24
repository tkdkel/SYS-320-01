# Storyline: An incident response tool that retrieves relevant information about the machine


# Prompt user for location to save results
$resultsDirectory = Read-Host "Please enter the directory where you want to save the results"

function file_hashes() {

    # Create the hashes for the coresponding files
    $hash = Get-FileHash -path $resultsDirectory/*csv -Algorithm SHA256

    # Create a new file inside specified directory which creates a checksum for the hashes
    $hash | Out-file $resultsDirectory\checksum.txt

}


# Running processes and path for each process
$filePath = Join-Path -Path $resultsDirectory -ChildPath "processes.csv"
Get-Process | Select-Object Name, Path | Export-Csv -Path $filePath -NoTypeInformation

# All registered services and the path to the executable controlling the service
$servicePath = Join-Path -Path $resultsDirectory -ChildPath "services.csv"
Get-WmiObject -Class Win32_Service | Select-Object Name, PathName | Export-Csv -Path $servicePath -NoTypeInformation

# All TCP network sockets
$tcpPath = Join-Path -Path $resultsDirectory -ChildPath "tcpSockets.csv"
Get-NetTCPConnection | Export-Csv -Path $tcpPath -NoTypeInformation 

# All user account information
$userAccountPath = Join-Path -Path $resultsDirectory -ChildPath "userAccounts.csv"
Get-WmiObject -Class Win32_UserAccount | Export-Csv -Path $userAccountPath -NoTypeInformation

# All NetworkAdapterConfiguration information
$networkAdapterPath = Join-Path -Path $resultsDirectory -ChildPath "networkAdapterConfiguration.csv"
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Export-Csv -Path $networkAdapterPath -NoTypeInformation


# Use Powershell cmdlets to save 4 other artifacts that would be useful in an incident but only use Powershell cmdlets
# In your code comment, explain why you selected those four cmdlets and the value it would provide for an incident investigation


# Security event logs - can be useful when trying to look at activities done on the computer
$secEventLogs = Join-Path $resultsDirectory -ChildPath "securityEventLogs.csv"
Get-EventLog -LogName Security | Export-Csv -Path $secEventLogs -NoTypeInformation

# Report of all threats detected by Windows Antivirus - important for showing immediate threats
$threatDetection = Join-Path $resultsDirectory -ChildPath "antivirusThreatDetection.csv"
Get-MpThreatDetection | Export-Csv -Path $threatDetection -NoTypeInformation

# Command line history - useful for checking what commands have been input
$cmdHistory = Join-Path $resultsDirectory -ChildPath "cmdLineHistory.csv"
Get-History | select Id, CommandLine, ExecutionStatus, StartExecutionTime, EndExecutionTime | Export-Csv -Path $cmdHistory -NoTypeInformation

# Firewall rules - good for preventative measures and to see if there are any holes that can be poked in the firewall
$firewallRules = Join-Path $resultsDirectory -ChildPath "firewallRules.csv"
Get-NetFirewallRule | Export-Csv -Path $firewallRules -NoTypeInformation


# Create name of the zip file and put it in the directory the user specified
$zipFile = "$resultsDirectory\resultsZip.zip"

# Compress the directory
Compress-Archive -Path $resultsDirectory\* -DestinationPath $zipFile -Force

# Create a hash for the zip
$zipFileHash = Get-FileHash -Path $zipFile -Algorithm SHA256

# Take the hash table associated with the zip and place it in the directory specified by the user
$zipFileHash | Out-File $resultsDirectory\zipFileHash.txt

# Call hashing function
file_hashes