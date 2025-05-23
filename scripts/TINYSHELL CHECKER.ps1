# TINYSHELL Detection Script

Function Get-SuspiciousPowerShellCommands {
    $suspiciousPatterns = @(
        'IEX\s*\(',                       # Invoke-Expression
        'New-Object\s+Net.WebClient',    # Download via WebClient
        '\[System\.Net\.WebRequest\]',   # Another download method
        'FromBase64String',              # Encoded payloads
        'Invoke-Expression',             # Direct execution of code
        'Invoke-Command',                # Remote code execution
        'Set-Content\s+-Path\s+\$env:TEMP', # Dropping files to TEMP
        'Add-Type\s+\-TypeDefinition',   # Injecting .NET code
        'Win32_ProcessStartup',          # WMI-based process spawning
        'powershell\.exe\s+-enc',        # Base64 encoded payloads
        'Invoke-WebRequest',             # Common download tool
        'Start-Process.*cmd\.exe'        # Command shell execution
    )

    Write-Host "🔍 Scanning PowerShell history and logs for suspicious patterns..." -ForegroundColor Cyan

    # Get PowerShell History (if available)
    $historyPaths = @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
        "$env:HOMEPATH\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    )

    foreach ($path in $historyPaths) {
        if (Test-Path $path) {
            Get-Content $path | ForEach-Object {
                $line = $_
                foreach ($pattern in $suspiciousPatterns) {
                    if ($line -match $pattern) {
                        Write-Output "`n[!] Suspicious Command Found:"
                        Write-Output "    Pattern : $pattern"
                        Write-Output "    Command : $line"
                    }
                }
            }
        }
    }

    # Check running PowerShell processes for encoded commands
    $psProcs = Get-WmiObject Win32_Process | Where-Object { $_.Name -match 'powershell' }
    foreach ($proc in $psProcs) {
        if ($proc.CommandLine -match 'encodedcommand') {
            Write-Output "`n[!] Suspicious PowerShell Process:"
            Write-Output "    PID     : $($proc.ProcessId)"
            Write-Output "    Command : $($proc.CommandLine)"
        }
    }
}

Function Scan-NetworkConnections {
    Write-Host "🔍 Scanning for suspicious network connections from PowerShell..." -ForegroundColor Cyan
    $connections = Get-NetTCPConnection | Where-Object { $_.OwningProcess -ne 0 }
    foreach ($conn in $connections) {
        try {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
            if ($proc.ProcessName -match "powershell") {
                Write-Output "`n[!] Suspicious Network Activity:"
                Write-Output "    Process    : $($proc.ProcessName)"
                Write-Output "    PID        : $($proc.Id)"
                Write-Output "    Remote IP  : $($conn.RemoteAddress)"
                Write-Output "    Remote Port: $($conn.RemotePort)"
            }
        } catch {
            continue
        }
    }
}

# Main Execution
Write-Host "`n=== TINYSHELL Malware Detection Script ===`n" -ForegroundColor Green
Get-SuspiciousPowerShellCommands
Scan-NetworkConnections
Write-Host "`n✅ Scan completed.`n" -ForegroundColor Green
