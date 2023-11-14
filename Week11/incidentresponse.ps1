# Storyline: An incident response tool that retrieves relevant information about the machine


# Function to get file hashes
function file_hashes {

    param ([string]$filePath)
    Get-ChildItem -Path $filePath -Filter *.csv | ForEach-Object {

        $hash = Get-FileHash -Path $_.FullName -Algorithm SHA1
        "$($hash.Hash)  $($_.Name)"

    }
}


function save_results {

    param ([string]$filePath)

    #Running processes and path for each process
    Get-Process | Select-Object ProcessName, Path, ID | Export-Csv -Path "$filePath\processes.csv" -NoTypeInformation

    # All registered services and the path to the executable controlling the service
    Get-WmiObject -Query "SELECT * FROM Win32_Service" | Select-Object DisplayName, PathName | Export-Csv -Path "$filePath\services.csv" -NoTypeInformation

    # All TCP network sockets
    Get-NetTCPConnection | Export-Csv -Path "$filePath\tcp-sockets.csv" -NoTypeInformation 

    # All user account information
    Get-WmiObject -Class Win32_UserAccount | Export-Csv -Path "$filePath\user-info.csv" -NoTypeInformation

    # All NetworkAdapterConfiguration information
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object @{n='IPAddress';e={$_.IPAddress -join ', '}}, `
    DHCPServer, @{n='DefaultIPGateway';e={$_.DefaultIPGateway -join ', '}}, @{n='DNSServerSearchOrder';e={$_.DNSServerSearchOrder -join ', '}} | `
    Export-Csv -Path "$filePath\network-info.csv" -NoTypeInformation


    # Use Powershell cmdlets to save 4 other artifacts that would be useful in an incident but only use Powershell cmdlets
    # In your code comment, explain why you selected those four cmdlets and the value it would provide for an incident investigation


    # Security event logs - can be useful when trying to look at activities done on the computer
    Get-EventLog -LogName Security -Newest 50 | select Timegenerated, InstanceID, Source, Message | Export-Csv -Path "$filePath\event-logs.csv" -NoTypeInformation

    # Report of all threats detected by Windows Antivirus - important for showing immediate threats
    Get-MpThreatDetection | Export-Csv -Path "$filePath\threat-detection.csv" -NoTypeInformation

    # Command line history - useful for checking what commands have been input
    Get-History | select Id, CommandLine, ExecutionStatus, StartExecutionTime, EndExecutionTime | Export-Csv -Path "$filePath\cmd-history.csv" -NoTypeInformation

    # Firewall rules - good for preventative measures and to see if there are any holes that can be poked in the firewall
    Get-NetFirewallRule | Export-Csv -Path "$filePath\firewall_rules.csv" -NoTypeInformation

}


# Create a prompt that asks the user for the location of where to save the results for the commands above
Write-Host "Please enter a directory to save the files to:"
$filePath = Read-Host


# Create directory if it does not exist
if (!(Test-Path -Path $filePath)) {

    New-Item -ItemType Directory -Path $filePath

}


# Create a 'FileHash' of the resulting CSV files, create a checksum for each one, and save the results to a file within the results directory
save_results -filePath $filePath
$fileHashes = Get-FileHash -Path $filePath
$fileHashes | Out-File -FilePath "$filePath\checksum.txt"


# Use the Powershell cmdlet Compress-Archive to zip the directory where the results are stored
$zipFile = "results.zip"
Compress-Archive -Path "$filePath\*" -DestinationPath "$filePath\$zipFile"
Write-Host "Compressed zip file created. File can be found at: $filePath\$zipFile"


# Create a checksum of the zipped file and save it to a file
$zipHash = Get-FileHash -Path "$filePath\$zipFile" -Algorithm SHA1
"$($zipHash.Hash)  $zipFile" | Out-File -FilePath "$filePath\$zipFile-checksum.txt"
Write-Host "Checksum file created. This can be located at: $filePath\$zipFile-checksum.txt"