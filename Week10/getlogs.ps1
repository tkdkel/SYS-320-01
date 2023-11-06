# Storyline: View the event logs, check for a valid log, and print the results

function select_log() {
    cls

    # List all event logs
    $theLogs = Get-EventLog -List | select Log
    $theLogs | Out-Host

    # Initialize the array to store the logs
    $arrLog = @()

    foreach ($tempLog in $theLogs) {
        
        #Add each log to the array
        # Note: These are stored in the array as a hashtable in the format:
        # @{Log=LOGNAME}
        $arrLog += $tempLog

    }

    # Test to be sure our array is being populated
    Write-Host $arrLog[0]

    # Prompt the user for the log to view or quit
    $readLog = read-host -Prompt "Please enter a log from the list above or 'q' to quit the program"

    # Check if the user wants to quit
    if ($readLog -match "^[qQ]$") {

        # Stop executing and close the script
        break

    }

    log_check -logToSearch $readLog

} # Ends the select_log()


function log_check() {
    
    # String the user types in within the select_log function
    Param([string]$logToSearch)

    # Format the user input
    $theLog = "^@{Log=" + $logToSearch + "}$"

    # Search the array for the exact hashtable string
    if ($arrLog -match $theLog) {

        Write-Host -BackgroundColor Green -ForegroundColor white "Please wait, it may take a few moments to retrieve the log entries."
        sleep 2

        # Call the function to view the log by passing the argument
        view_log -logToSearch $logToSearch

    } else {

        Write-Host -BackgroundColor Red -ForegroundColor White "The log specified does not exist."
        sleep 2
        select_log

    }
} # Ends the log_check()


function view_log() {

    cls
    Get-EventLog -Log $logToSearch -Newest 10 -After "1/18/2020"

    # Pause the screen and wait until the user is ready to proceed
    Read-Host -Prompt "Press enter when you are done"

    # Go back to select_log
    select_log

} # Ends the view_log()


function get_services() {

    cls
    $services = @('all', 'stopped', 'running')
    Write-Host "1. All"
    Write-Host "2. Stopped"
    Write-Host "3. Running"

    # Take user input and determine what option was selected
    $input = Read-Host -Prompt "Select an option (1, 2, or 3) to view or q to quit"

    # Output all services
    if ($input -eq "1") {

        Get-Service

    }

    # Output stopped services
    elseif ($input -eq "2") {

        Get-Service | Where-Object {$_.Status -eq "stopped"}

    }

    # Output running services
    elseif ($input -eq "3") {

        Get-Service | Where-Object {$_.Status -eq "running"}

    }

    # Quit
    elseif ($input -match "^[qQ]$") {

        break

    }

    # If invalid input, restarts function
    else {

        Write-Host "Invalid input. Restarting..."
        sleep 2
        get_services

    }
} # Ends get_services()


# Menu to choose between original code from video and code that was created for assignment
function menu() {

    cls
    Write-Host "1. Service Logs"
    Write-Host "2. System Logs"
    $input = Read-Host -Prompt "Please select an option (1 or 2) or press q to quit"

    # Calls get_services
    if ($input -eq "1") {

        get_services

    }

    # Calls select_log
    elseif ($input -eq "2") {

        select_log

    }

    # Quits the program
    elseif ($input -match "^[qQ]$") {

        break

    }

    # If invalid input, restarts function
    else {

        Write-Host "Invalid input. Restarting..."
        sleep 2
        menu

    }
} # Ends menu()

# Runs the menu to start the program
menu