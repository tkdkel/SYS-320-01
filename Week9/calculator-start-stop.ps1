# Write a program that can start and stop the Windows Calculator using Powershell and the process name for Windows Calculator

Start-Process calculator:
Start-Sleep -Seconds 5
Stop-Process -Name win32calc