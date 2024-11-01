# Function to check if running with elevated privileges (as Administrator)
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Function to relaunch the script as an Administrator, if not already elevated
function Ensure-Elevation {
    if (-not (Test-IsAdmin)) {
        Write-Log "Restarting script as Administrator."
        $newProcess = New-Object System.Diagnostics.ProcessStartInfo "powershell"
        $newProcess.Arguments = "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" 
        $newProcess.Verb = "runas"
        $newProcess.WindowStyle = "Hidden"
        [System.Diagnostics.Process]::Start($newProcess)
        exit
    }
}

# Get the current user's Documents folder
$documentsFolder = [Environment]::GetFolderPath("MyDocuments")
$blockListDir = Join-Path $documentsFolder "PeerBlockLists"

# Define the URLs of alternative blocklists
$blockListURLs = @(
    "https://www.spamhaus.org/drop/drop.lasso",                # Spamhaus DROP list
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",  # Emerging Threats block list
    "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist",     # Zeus Tracker IP blocklist
    "https://blocklist.de/downloads/blocklist_de.txt"          # blocklist.de
)

# Create the directory to store downloaded and extracted blocklists
New-Item -ItemType Directory -Force -Path $blockListDir

# Function to download blocklists
function Download-BlockList {
    param (
        [string]$url
    )

    $fileName = [System.IO.Path]::GetFileNameWithoutExtension([System.IO.Path]::GetRandomFileName()) + ".txt"
    $outputFile = Join-Path $blockListDir $fileName

    try {
        # Download the blocklist
        Invoke-WebRequest -Uri $url -OutFile $outputFile -ErrorAction Stop
        Write-Host "Downloaded: $url" -ForegroundColor Green
        return $outputFile
    } catch {
        Write-Host "Failed to download: $url" -ForegroundColor Red
        return $null
    }
}

# Function to parse and filter the IPs from the blocklist
function Parse-BlockList {
    param (
        [string]$filePath
    )

    $outputList = @()
    # Read the content and filter IP addresses (assuming the blocklists contain plain IP addresses)
    $outputList += Get-Content -Path $filePath | Where-Object { $_ -match "^\d{1,3}(\.\d{1,3}){3}" }
    return $outputList
}

# Function to add IP addresses or ranges to Windows Firewall for both inbound and outbound blocking
function Add-IPBlock {
    param (
        [string]$ipRange
    )

    $inboundRuleName = "Block IP Range (Inbound) - $ipRange"
    $outboundRuleName = "Block IP Range (Outbound) - $ipRange"

    # Block inbound traffic
    New-NetFirewallRule -DisplayName $inboundRuleName -Direction Inbound -Action Block -RemoteAddress $ipRange -Profile Any -Verbose
    
    # Block outbound traffic
    New-NetFirewallRule -DisplayName $outboundRuleName -Direction Outbound -Action Block -RemoteAddress $ipRange -Profile Any -Verbose
}

# Download and process each blocklist
$allBlockListIPs = @()

foreach ($url in $blockListURLs) {
    $downloadedFile = Download-BlockList -url $url
    if ($downloadedFile) {
        $parsedIPs = Parse-BlockList -filePath $downloadedFile
        $allBlockListIPs += $parsedIPs
    }
}

# Deduplicate IPs and block them
$uniqueIPs = $allBlockListIPs | Sort-Object -Unique

foreach ($ip in $uniqueIPs) {
    try {
        if ($ip.Trim() -eq "" -or $ip.Trim().StartsWith("#")) {
            continue
        }

        Add-IPBlock -ipRange $ip
        Write-Host "Blocked IP/Range: $ip" -ForegroundColor Green
    } catch {
        Write-Host "Failed to block IP/Range: $ip" -ForegroundColor Red
    }
}

Write-Host "IP blocking complete." -ForegroundColor Cyan

# Optional: Logging
$logFile = Join-Path $documentsFolder "block_log.txt"
$uniqueIPs | Out-File -FilePath $logFile -Append
Write-Host "Block list logged to $logFile" -ForegroundColor Yellow
