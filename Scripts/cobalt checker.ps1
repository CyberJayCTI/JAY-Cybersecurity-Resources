<#
.SYNOPSIS
Detects signs of Cobalt Strike activity on a Windows system.
#>

Write-Host "`n=== Cobalt Strike Detection Script (Blue Team) ===`n"

# 1. Detect suspicious parent-child process relationships
Write-Host "[*] Scanning for suspicious parent-child processes (powershell, rundll32, mshta, etc)...`n"
$watchList = @("powershell.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe", "cmd.exe", "msbuild.exe")
$parentProcs = Get-WmiObject Win32_Process | Where-Object {
    $_.Name -in $watchList
}

foreach ($proc in $parentProcs) {
    $children = Get-WmiObject Win32_Process | Where-Object { $_.ParentProcessId -eq $proc.ProcessId }
    foreach ($child in $children) {
        Write-Host "[!] Suspicious process tree: $($proc.Name) -> $($child.Name)" -ForegroundColor Yellow
    }
}

# 2. Scan memory for injected code (using AMSI bypass, hidden DLLs)
Write-Host "`n[*] Checking for suspicious memory modules in running processes..."
$injectedProcs = Get-Process | Where-Object {
    $_.Modules | Where-Object {
        $_.ModuleName -match ".*\.dll" -and $_.FileName -eq $null
    }
}

if ($injectedProcs) {
    foreach ($proc in $injectedProcs) {
        Write-Host "[!] Process $($proc.ProcessName) may have reflective DLL injection" -ForegroundColor Red
    }
} else {
    Write-Host "[+] No obvious injected DLLs found." -ForegroundColor Green
}

# 3. Look for common beaconing intervals in Netstat
Write-Host "`n[*] Checking for beaconing behavior (frequent connections to same IP)..."
$connections = Get-NetTCPConnection -State Established | Group-Object -Property RemoteAddress

foreach ($group in $connections) {
    if ($group.Count -gt 5) {
        Write-Host "[!] Frequent connections to $($group.Name) ($($group.Count) connections)" -ForegroundColor Yellow
    }
}

# 4. Scan known locations for suspicious binaries
Write-Host "`n[*] Scanning AppData and Temp for potentially staged payloads..."

$paths = @("$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA")
foreach ($path in $paths) {
    Get-ChildItem -Path $path -Recurse -Include *.exe, *.dll -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Length -gt 1000000) {
            Write-Host "[!] Large binary in $($path): $($_.FullName)" -ForegroundColor Yellow
        }
    }
}

# 5. List known living-off-the-land (LOLBins) used in attacks
Write-Host "`n[*] Checking for execution of known LOLBins recently..."
$lolbins = @("regsvr32.exe", "mshta.exe", "rundll32.exe", "powershell.exe", "certutil.exe", "wmic.exe")
$log = Get-WinEvent -LogName Security -MaxEvents 1000 | Where-Object {
    $_.Message -match "New Process" -and $lolbins | ForEach-Object { $_.ToLower() -in $_.Message.ToLower() }
}

if ($log) {
    Write-Host "[!] LOLBins have been executed recently — investigate:" -ForegroundColor Red
    $log | Select-Object -First 10 | ForEach-Object { Write-Host $_.Message.Substring(0, 300) }
} else {
    Write-Host "[+] No recent suspicious LOLBin use detected." -ForegroundColor Green
}

Write-Host "`n=== Scan Complete ===`n"
