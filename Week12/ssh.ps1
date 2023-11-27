# Storyline: Script to login to a remote SSH server
# NOTE: The SSH server used for this week's assignment is currently down. This code should work, in theory, if the server was up

New-SSHSession -ComputerName '192.168.4.22' -Credential (Get-Credential sys320)


while ($true) {

    # Add a prompt to run the commands
    $command = Read-Host -Prompt "Please enter a command"

    # Run command on remote SSH server
    (Invoke-SSHCommand -index 0 $command).Output

}


Set-SCPFile -ComputerName '192.168.4.22' -Credential (Get-Credential sys320) `
-RemotePath '/home/SYS-320-01' -LocalFile '.tedx.jpeg'