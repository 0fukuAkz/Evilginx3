#Requires -RunAsAdministrator

#############################################################################
# Evilginx 3.3.1 - Private Dev Edition - Windows Uninstaller
#############################################################################
# This script completely removes Evilginx and cleans up all traces
#
# What this script does:
# - Stops and removes the Windows Service
# - Removes the Evilginx binary and files
# - Removes firewall rules
# - Cleans up configuration and logs
# - Removes helper scripts
# - Optionally removes Go and NSSM
#
# Usage:
#   Right-click PowerShell -> Run as Administrator
#   .\uninstall-windows.ps1
#
# Author: AKaZA (Akz0fuku)
# Version: 1.0.0
#############################################################################

$ErrorActionPreference = "Stop"

# Colors
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Info($message) {
    Write-ColorOutput Cyan "[INFO] $message"
}

function Write-Success($message) {
    Write-ColorOutput Green "[✓] $message"
}

function Write-Warning($message) {
    Write-ColorOutput Yellow "[!] $message"
}

function Write-Error($message) {
    Write-ColorOutput Red "[✗] $message"
}

function Write-Step($message) {
    Write-Output ""
    Write-ColorOutput Cyan "═══════════════════════════════════════════════════════════"
    Write-ColorOutput Cyan "▶ $message"
    Write-ColorOutput Cyan "═══════════════════════════════════════════════════════════"
    Write-Output ""
}

# Configuration (must match install-windows.ps1)
$INSTALL_DIR = "C:\Evilginx"
$CONFIG_DIR = "$env:USERPROFILE\.evilginx"
$LOG_DIR = "$INSTALL_DIR\logs"
$SERVICE_NAME = "Evilginx"
$SCRIPTS_DIR = "$env:ProgramFiles\Evilginx"

function Show-Banner {
    Write-ColorOutput Magenta @"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     ███████╗██╗   ██╗██╗██╗      ██████╗ ██╗███╗   ██╗██╗  ██╗  ║
║     ██╔════╝██║   ██║██║██║     ██╔════╝ ██║████╗  ██║╚██╗██╔╝  ║
║     █████╗  ██║   ██║██║██║     ██║  ███╗██║██╔██╗ ██║ ╚███╔╝   ║
║     ██╔══╝  ╚██╗ ██╔╝██║██║     ██║   ██║██║██║╚██╗██║ ██╔██╗   ║
║     ███████╗ ╚████╔╝ ██║███████╗╚██████╔╝██║██║ ╚████║██╔╝ ██╗  ║
║     ╚══════╝  ╚═══╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝  ║
║                                                                   ║
║                        UNINSTALLER                                ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"@
    Write-Output ""
}

function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run as Administrator!"
        Write-Info "Right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
    Write-Success "Running as Administrator"
}

function Confirm-Uninstall {
    Write-Warning @"

⚠️  WARNING: This will completely remove Evilginx from your system!

The following will be deleted:
   • Windows Service: $SERVICE_NAME
   • Installation directory: $INSTALL_DIR
   • Configuration directory: $CONFIG_DIR
   • Log directory: $LOG_DIR
   • Helper scripts in $SCRIPTS_DIR
   • All captured sessions and data

⚠️  This action CANNOT be undone!

"@
    
    $response = Read-Host "Are you sure you want to uninstall Evilginx? (yes/NO)"
    if ($response -ne "yes") {
        Write-Error "Uninstall cancelled by user"
        exit 0
    }
}

function Stop-Service {
    Write-Step "Step 1: Stopping Evilginx Service"
    
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Info "Stopping service..."
            Stop-Service -Name $SERVICE_NAME -Force
            Start-Sleep -Seconds 2
            Write-Success "Service stopped"
        } else {
            Write-Info "Service not running"
        }
    } else {
        Write-Info "Service not found"
    }
}

function Remove-Service {
    Write-Step "Step 2: Removing Windows Service"
    
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($service) {
        $nssmExe = Get-ChildItem -Path "$INSTALL_DIR\nssm" -Filter "nssm.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        
        if ($nssmExe -and (Test-Path $nssmExe)) {
            Write-Info "Removing service using NSSM..."
            & $nssmExe remove $SERVICE_NAME confirm
            Start-Sleep -Seconds 2
            Write-Success "Service removed"
        } else {
            Write-Warning "NSSM not found, trying sc.exe..."
            sc.exe delete $SERVICE_NAME
            Start-Sleep -Seconds 2
            Write-Success "Service removed"
        }
    } else {
        Write-Info "Service not found"
    }
}

function Remove-Files {
    Write-Step "Step 3: Removing Installation Files"
    
    if (Test-Path $INSTALL_DIR) {
        Write-Warning "Removing $INSTALL_DIR..."
        
        # Backup configuration if it exists
        if (Test-Path "$CONFIG_DIR\config.json") {
            $backup = "$env:TEMP\evilginx_config_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
            Write-Info "Backing up configuration to: $backup"
            Compress-Archive -Path "$CONFIG_DIR\*" -DestinationPath $backup -ErrorAction SilentlyContinue
            if (Test-Path $backup) {
                Write-Success "Configuration backed up"
            }
        }
        
        Remove-Item -Path $INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue
        Write-Success "Installation directory removed"
    } else {
        Write-Info "Installation directory not found"
    }
    
    if (Test-Path $CONFIG_DIR) {
        Write-Warning "Removing configuration: $CONFIG_DIR"
        Remove-Item -Path $CONFIG_DIR -Recurse -Force -ErrorAction SilentlyContinue
        Write-Success "Configuration directory removed"
    }
}

function Remove-HelperScripts {
    Write-Step "Step 4: Removing Helper Scripts"
    
    if (Test-Path $SCRIPTS_DIR) {
        Write-Info "Removing helper scripts..."
        Remove-Item -Path $SCRIPTS_DIR -Recurse -Force -ErrorAction SilentlyContinue
        
        # Remove from PATH
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        $newPath = ($currentPath -split ';' | Where-Object { $_ -ne $SCRIPTS_DIR }) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
        
        Write-Success "Helper scripts removed"
    } else {
        Write-Info "Helper scripts directory not found"
    }
}

function Remove-FirewallRules {
    Write-Step "Step 5: Removing Firewall Rules"
    
    Write-Output ""
    $response = Read-Host "Remove firewall rules for ports 53, 80, 443? (y/N)"
    
    if ($response -eq "y" -or $response -eq "Y") {
        Write-Info "Removing firewall rules..."
        
        Remove-NetFirewallRule -DisplayName "Evilginx DNS TCP" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "Evilginx DNS UDP" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "Evilginx HTTP" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "Evilginx HTTPS" -ErrorAction SilentlyContinue
        
        Write-Success "Firewall rules removed"
    } else {
        Write-Info "Firewall rules kept (skipped)"
    }
}

function Secure-DeleteData {
    Write-Step "Step 6: Secure Data Deletion"
    
    Write-Output ""
    $response = Read-Host "Securely wipe all Evilginx data? (recommended for post-engagement) (y/N)"
    
    if ($response -eq "y" -or $response -eq "Y") {
        Write-Warning "Performing secure deletion (this may take time)..."
        
        # Find and securely delete database files
        $dbFiles = Get-ChildItem -Path $env:TEMP, $env:USERPROFILE -Filter "*.db" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -like "*evilginx*" }
        foreach ($file in $dbFiles) {
            Write-Info "Securely deleting: $($file.FullName)"
            # Use cipher.exe for secure deletion (overwrites with zeros)
            cipher.exe /w:$($file.DirectoryName) | Out-Null
            Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
        }
        
        # Clear event logs related to Evilginx
        Get-WinEvent -ListLog * | Where-Object { $_.LogName -like "*Evilginx*" } | ForEach-Object {
            Clear-EventLog -LogName $_.LogName -ErrorAction SilentlyContinue
        }
        
        Write-Success "Secure deletion completed"
    } else {
        Write-Info "Secure deletion skipped"
    }
}

function Remove-Go {
    Write-Step "Step 7: Remove Go (Optional)"
    
    Write-Output ""
    $response = Read-Host "Remove Go programming language? (y/N)"
    
    if ($response -eq "y" -or $response -eq "Y") {
        if (Test-Path "C:\Program Files\Go") {
            Write-Info "Removing Go..."
            Remove-Item -Path "C:\Program Files\Go" -Recurse -Force -ErrorAction SilentlyContinue
            
            # Remove from PATH
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            $newPath = ($currentPath -split ';' | Where-Object { $_ -notlike "*\Go\bin*" }) -join ';'
            [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
            
            Write-Success "Go removed"
        } else {
            Write-Info "Go not found"
        }
    } else {
        Write-Info "Go kept (skipped)"
    }
}

function Show-Completion {
    Write-Output ""
    Write-ColorOutput Green "╔═══════════════════════════════════════════════════════════════════╗"
    Write-ColorOutput Green "║                                                                   ║"
    Write-ColorOutput Green "║          ✓ UNINSTALLATION COMPLETED SUCCESSFULLY!                ║"
    Write-ColorOutput Green "║                                                                   ║"
    Write-ColorOutput Green "╚═══════════════════════════════════════════════════════════════════╝"
    Write-Output ""
    
    Write-Step "Uninstallation Summary"
    
    Write-ColorOutput Cyan "Removed:"
    Write-Output "  ✓ Evilginx service"
    Write-Output "  ✓ Installation files ($INSTALL_DIR)"
    Write-Output "  ✓ Configuration files ($CONFIG_DIR)"
    Write-Output "  ✓ Log files ($LOG_DIR)"
    Write-Output "  ✓ Helper scripts"
    Write-Output ""
    
    $backups = Get-ChildItem -Path $env:TEMP -Filter "evilginx_config_backup_*.zip" -ErrorAction SilentlyContinue
    if ($backups) {
        Write-ColorOutput Yellow "Backup created:"
        foreach ($backup in $backups) {
            Write-Output "  $($backup.FullName)"
        }
        Write-Output ""
    }
    
    Write-ColorOutput Yellow "Post-Uninstall Recommendations:"
    Write-Output ""
    Write-Output "  • Review firewall rules: Get-NetFirewallRule | Where-Object DisplayName -like '*Evilginx*'"
    Write-Output "  • Check for remaining files: Get-ChildItem -Path C:\ -Filter '*evilginx*' -Recurse -ErrorAction SilentlyContinue"
    Write-Output "  • Remove DNS records from Cloudflare"
    Write-Output "  • Delete domain or let it expire"
    Write-Output "  • Review Windows Event Logs"
    Write-Output ""
    
    Write-Success "Evilginx has been completely removed from your system"
}

function Main {
    Show-Banner
    
    Test-Administrator
    Confirm-Uninstall
    
    Stop-Service
    Remove-Service
    Remove-Files
    Remove-HelperScripts
    Remove-FirewallRules
    Secure-DeleteData
    Remove-Go
    
    Show-Completion
}

try {
    Main
} catch {
    Write-Error "Uninstall failed: $_"
    Write-Output $_.ScriptStackTrace
    exit 1
}

exit 0

