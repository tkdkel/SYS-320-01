# Array of websites containing threat intell
$drop_urls = @('https://rules.emergingthreats.net/blockrules/emerging-botcc.rules', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt')

# Loop through the URLs for the rules list
foreach ($u in $drop_urls) {

    # Extract the filename
    $temp = $u.Split("/")

    # The last element in the array plucked off is the filename
    $file_name = $temp[-1]

    if (Test-Path $file_name) {

        continue

    } else {

        # Download the rules list
        Invoke-WebRequest -Uri $u -OutFile  $file_name

    }
}

# Array containing the filename
$input_paths = @('.\compromised-ips.txt', '.\emerging-botcc.rules')

# Extract the IP addresses
# 108.190.109.107
# 108.191.2.72
$regex_drop = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

# Append the IP addresses to the temporary IP list
Select-String -Path $input_paths -Pattern $regex_drop | `
ForEach-Object { $_.Matches } | `
ForEach-Object { $_.Value } | Sort-Object | Get-Unique | `
Out-File -FilePath "ips-bad.tmp"

# User input for OS
$os = Read-Host "Please select an Operating System to generate a ruleset (1 for IPTables, 2 for Windows Firewall)"

# Switch statement for generating firewall rules
switch ($os) {

    '1' {
(Get-Content -Path ".\ips-bad.tmp") | ForEach-Object `
        { $_ -replace "^", "iptables -A INPUT -s " -replace "$", " -j DROP" } | `
            Out-File -FilePath "iptables-rules.bash"
    }
    '2' {
(Get-Content -Path ".\ips-bad.tmp") | ForEach-Object `
        { $_ -replace "^", 'netsh advfirewall firewall add rule name="BLACKLIST" dir=in action=block remoteip=' } | `
            Out-File -FilePath "firewall-rules.ps1"
    }
}