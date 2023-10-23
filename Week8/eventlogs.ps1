# Storyline: Review the Security Event log

# Directory to save files:
$myDir = "C:\Users\champuser\Desktop"

# List all the available Windows Event logs
Get-EventLog -List

# Create a prompt to allow user to select the Log to view
$readLog = Read-Host -Prompt "Please select a log to review from the list above"

# Create a prompt that allows the user to specify a keyword or phrase to search on.
$getPhrase = Read-Host -Prompt "Please specify a keyword or phrase to search for"

# Print the results for the log
Get-EventLog -LogName $readLog -Newest 40 | where {$_.Message -ilike "*$getPhrase*" } | export-csv -NoTypeInformation `
-Path "$myDir\securityLogs.csv"