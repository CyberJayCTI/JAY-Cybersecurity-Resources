# Mimikatz Indicator Checker with Logging
$logFile = "$env:USERPROFILE\mimikatz_scan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
"[*] Mimikatz Scan Started: $(Get-Date)" | Out-File -FilePath $logFile -Encoding UTF8

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $formatted = "[$Level] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message"
    Write-Host $formatted
    $formatted | Out-File -FilePath $logFile -Append -Encoding UTF8
}

function Check-MimikatzFiles {
    Write-Log "`n[+] Checking for known Mimikatz files..." "INFO"
    $paths = @("$env:TEMP", "$env:USERPROFILE\Downloads", "C:\Windows\Temp", "C:\")
    $suspiciousNames = @("mimikatz.exe", "mimilib.dll", "mimikatz.log")
    foreach ($path in $paths) {
        foreach ($name in $suspiciousNames) {
            $found = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $name }
            if ($found) {
                foreach ($file in $found) {
                    Write-Log "Found suspicious file: $($file.FullName)" "WARN"
                }
            }
        }
    }
}

function Check-LSASSModules {
    Write-Log "`n[+] Checking LSASS for suspicious modules..." "INFO"
    $lsass = Get-Process -Name lsass -ErrorAction SilentlyContinue
    if ($lsass) {
        try {
            $modules = ($lsass.Modules | Select-Object ModuleName, FileName)
            $suspicious = $modules | Where-Object { $_.FileName -match "mimilib" }
            if ($suspicious) {
                foreach ($mod in $suspicious) {
                    Write-Log "Suspicious module loaded in LSASS: $($mod.FileName)" "WARN"
                }
            } else {
                Write-Log "No suspicious modules found in LSASS." "OK"
            }
        } catch {
            Write-Log "Access denied to LSASS modules. Run as administrator." "ERROR"
        }
    } else {
        Write-Log "LSASS process not found." "ERROR"
    }
}

function Check-EventLogs {
    Write-Log "`n[+] Checking Security Event Logs for suspicious entries..." "INFO"
    try {
        $events = Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object {
            $_.Message -match "mimikatz"
        }
        if ($events) {
            foreach ($event in $events) {
                Write-Log "Suspicious log found: Event ID $($event.Id) at $($event.TimeCreated)" "WARN"
            }
        } else {
            Write-Log "No suspicious event log entries found." "OK"
        }
    } catch {
        Write-Log "Unable to read Security logs. Requires administrative privileges." "ERROR"
    }
}

function Check-NetworkIndicators {
    Write-Log "`n[+] Checking for network-based indicators..." "INFO"
    try {
        $kerbEvents = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4769)]]" -MaxEvents 1000 |
            Where-Object { $_.Message -match "krbtgt" -or $_.Message -match "RC4-HMAC" }

        if ($kerbEvents.Count -gt 0) {
            Write-Log "Unusual Kerberos ticket requests detected (Event ID 4769):" "WARN"
            foreach ($e in $kerbEvents | Select-Object -First 5) {
                Write-Log "  -> $($e.TimeCreated): $($e.Message -split "`n")[0]" "WARN"
            }
        }

        $ntlmEvents = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624 or EventID=4776)]]" -MaxEvents 1000 |
            Where-Object { $_.Message -match "NTLM" -and $_.Message -match "Logon Type:\s+3" }

        if ($ntlmEvents.Count -gt 10) {
            Write-Log "Multiple NTLM logons detected (Event ID 4624/4776):" "WARN"
            foreach ($e in $ntlmEvents | Select-Object -First 5) {
                Write-Log "  -> $($e.TimeCreated): $($e.Message -split "`n")[0]" "WARN"
            }
        }

        $shares = Get-WinEvent -LogName Security -MaxEvents 500 |
            Where-Object { $_.Message -match "\\\\.*\\admin\$|\\\\.*\\c\$" }

        if ($shares.Count -gt 0) {
            Write-Log "Admin share access attempts detected:" "WARN"
            foreach ($e in $shares | Select-Object -First 5) {
                Write-Log "  -> $($e.TimeCreated): $($e.Message -split "`n")[0]" "WARN"
            }
        }

    } catch {
        Write-Log "Error reading Security logs for network indicators. Try running as admin." "ERROR"
    }
}

# Run all checks
Check-MimikatzFiles
Check-LSASSModules
Check-EventLogs
Check-NetworkIndicators

Write-Log "`nScan complete." "INFO"
Write-Log "Log saved to: $logFile" "INFO"
