# Storyline: Using the Get-process and Get-service
# Get-Process | Select-Object ProcessName, Path, ID |
# Export-Csv -Path "C:\users\champuser\Desktop\myProcesses.csv" -NoTypeInformation
# Get-Process | Get-Member
# Get-Service | Where { $_.Status -eq "Stopped" }

Get-Process| Select-Object ProcessName, Path, ID |`
Export-Csv -Path "C:\Users\champuser\SYS-320-01\Week9\myProcesses.csv" -NoTypeInformation

Get-Service | Where-Object { $_.Status -eq "Running" } |`
Export-Csv -Path "C:\Users\champuser\SYS-320-01\Week9\myServices.csv" -NoTypeInformation