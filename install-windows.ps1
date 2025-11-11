#Requires -RunAsAdministrator

#############################################################################
# Evilginx 3.3.1 - Private Dev Edition - Windows Service Installer
#############################################################################
# This script automates the complete installation and configuration process
# for Windows systems, including Windows Service creation
#
# What this script does:
# - Installs Go (if not present)
# - Builds Evilginx from source
# - Creates Windows Service using NSSM
# - Configures Windows Firewall rules
# - Creates helper scripts
# - Sets up automatic startup
#
# Usage:
#   Right-click PowerShell -> Run as Administrator
#   .\install-windows.ps1
#
# Author: AKaZA (Akz0fuku)
# Version: 1.0.0
#############################################################################

$ErrorActionPreference = "Stop"

# Colors for output
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

# Configuration
$GO_VERSION = "1.22.0"
$INSTALL_DIR = "C:\Evilginx"
$CONFIG_DIR = "$env:USERPROFILE\.evilginx"
$LOG_DIR = "$INSTALL_DIR\logs"
$PHISHLETS_DIR = "$INSTALL_DIR\phishlets"
$REDIRECTORS_DIR = "$INSTALL_DIR\redirectors"
$SERVICE_NAME = "Evilginx"
$NSSM_VERSION = "2.24"
$NSSM_URL = "https://nssm.cc/release/nssm-${NSSM_VERSION}.zip"

# Banner
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
║          Windows Service Installer - Private Dev Edition         ║
║                         Version 3.3.1                             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"@
    Write-Output ""
}

# Check Administrator
function Test-Administrator {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script must be run as Administrator!"
        Write-Info "Right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
    Write-Success "Running as Administrator"
}

# Confirm installation
function Confirm-Installation {
    Write-Warning @"

⚠️  WARNING: This installer will make significant system changes:

   1. Install Go $GO_VERSION (if not present)
   2. Build Evilginx from source
   3. Stop conflicting services (if any)
   4. Configure Windows Firewall (ports 53, 80, 443)
   5. Create Windows Service: $SERVICE_NAME
   6. Enable automatic startup
   7. Install NSSM (Non-Sucking Service Manager)

⚠️  LEGAL NOTICE:
   This tool is for AUTHORIZED SECURITY TESTING ONLY.
   Unauthorized use is ILLEGAL and UNETHICAL.
   You are responsible for compliance with all applicable laws.

"@
    
    $response = Read-Host "Do you have WRITTEN AUTHORIZATION to deploy this tool? (yes/NO)"
    if ($response -ne "yes") {
        Write-Error "Installation cancelled. Authorization required."
        exit 1
    }
    
    $response = Read-Host "Proceed with installation? (yes/NO)"
    if ($response -ne "yes") {
        Write-Error "Installation cancelled by user"
        exit 1
    }
}

# Install Go
function Install-Go {
    Write-Step "Step 1: Installing Go $GO_VERSION"
    
    if (Get-Command go -ErrorAction SilentlyContinue) {
        $version = (go version).Split(' ')[2]
        Write-Success "Go already installed: $version"
        return
    }
    
    Write-Info "Downloading Go $GO_VERSION..."
    $goZip = "$env:TEMP\go${GO_VERSION}.windows-amd64.zip"
    $goUrl = "https://go.dev/dl/go${GO_VERSION}.windows-amd64.zip"
    
    try {
        Invoke-WebRequest -Uri $goUrl -OutFile $goZip -UseBasicParsing
        Write-Success "Downloaded Go"
    } catch {
        Write-Error "Failed to download Go: $_"
        exit 1
    }
    
    Write-Info "Extracting Go to C:\Program Files\Go..."
    Expand-Archive -Path $goZip -DestinationPath "C:\Program Files" -Force
    Remove-Item $goZip -Force
    
    # Add to PATH
    $goPath = "C:\Program Files\Go\bin"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$goPath*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$goPath", "Machine")
        $env:Path += ";$goPath"
    }
    
    Write-Success "Go installed successfully"
    & "C:\Program Files\Go\bin\go.exe" version
}

# Install NSSM
function Install-NSSM {
    Write-Step "Step 2: Installing NSSM (Non-Sucking Service Manager)"
    
    $nssmDir = "$INSTALL_DIR\nssm"
    $nssmExe = "$nssmDir\nssm.exe"
    
    if (Test-Path $nssmExe) {
        Write-Success "NSSM already installed"
        return $nssmExe
    }
    
    Write-Info "Downloading NSSM $NSSM_VERSION..."
    $nssmZip = "$env:TEMP\nssm-${NSSM_VERSION}.zip"
    
    try {
        Invoke-WebRequest -Uri $NSSM_URL -OutFile $nssmZip -UseBasicParsing
        Write-Success "Downloaded NSSM"
    } catch {
        Write-Error "Failed to download NSSM: $_"
        exit 1
    }
    
    Write-Info "Extracting NSSM..."
    New-Item -ItemType Directory -Path $nssmDir -Force | Out-Null
    Expand-Archive -Path $nssmZip -DestinationPath $nssmDir -Force
    Remove-Item $nssmZip -Force
    
    # Find nssm.exe (it's in a subdirectory)
    $nssmExe = Get-ChildItem -Path $nssmDir -Filter "nssm.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName
    
    if (-not $nssmExe) {
        Write-Error "NSSM executable not found after extraction"
        exit 1
    }
    
    Write-Success "NSSM installed: $nssmExe"
    return $nssmExe
}

# Build Evilginx
function Build-Evilginx {
    Write-Step "Step 3: Building Evilginx"
    
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    
    Write-Info "Building from: $scriptDir"
    
    # Check if main.go exists
    if (-not (Test-Path "$scriptDir\main.go")) {
        Write-Error "main.go not found in $scriptDir"
        Write-Error "Please run this script from the Evilginx root directory"
        exit 1
    }
    
    Push-Location $scriptDir
    
    try {
        Write-Info "Downloading Go modules..."
        & "C:\Program Files\Go\bin\go.exe" mod download
        Write-Success "Dependencies downloaded"
        
        Write-Info "Compiling Evilginx..."
        & "C:\Program Files\Go\bin\go.exe" build -o "build\evilginx.exe" main.go
        
        if (-not (Test-Path "build\evilginx.exe")) {
            Write-Error "Build failed - binary not created"
            exit 1
        }
        
        Write-Success "Evilginx compiled successfully"
    } finally {
        Pop-Location
    }
}

# Install files
function Install-Files {
    Write-Step "Step 4: Installing Files"
    
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    
    Write-Info "Creating installation directory: $INSTALL_DIR"
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
    New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
    
    Write-Info "Copying files..."
    Copy-Item "$scriptDir\build\evilginx.exe" "$INSTALL_DIR\" -Force
    Copy-Item "$scriptDir\phishlets" "$INSTALL_DIR\" -Recurse -Force
    Copy-Item "$scriptDir\redirectors" "$INSTALL_DIR\" -Recurse -Force
    
    # Copy documentation
    Copy-Item "$scriptDir\README.md" "$INSTALL_DIR\" -ErrorAction SilentlyContinue
    Copy-Item "$scriptDir\DEPLOYMENT_GUIDE.md" "$INSTALL_DIR\" -ErrorAction SilentlyContinue
    Copy-Item "$scriptDir\LURE_RANDOMIZATION_GUIDE.md" "$INSTALL_DIR\" -ErrorAction SilentlyContinue
    
    Write-Success "Files installed to $INSTALL_DIR"
}

# Configure Windows Firewall
function Configure-Firewall {
    Write-Step "Step 5: Configuring Windows Firewall"
    
    Write-Info "Adding firewall rules..."
    
    # Remove existing rules if they exist
    Remove-NetFirewallRule -DisplayName "Evilginx DNS TCP" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "Evilginx DNS UDP" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "Evilginx HTTP" -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "Evilginx HTTPS" -ErrorAction SilentlyContinue
    
    # Add new rules
    New-NetFirewallRule -DisplayName "Evilginx DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow | Out-Null
    Write-Success "Firewall rule added: DNS TCP (port 53)"
    
    New-NetFirewallRule -DisplayName "Evilginx DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow | Out-Null
    Write-Success "Firewall rule added: DNS UDP (port 53)"
    
    New-NetFirewallRule -DisplayName "Evilginx HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow | Out-Null
    Write-Success "Firewall rule added: HTTP (port 80)"
    
    New-NetFirewallRule -DisplayName "Evilginx HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow | Out-Null
    Write-Success "Firewall rule added: HTTPS (port 443)"
    
    Write-Success "Windows Firewall configured"
}

# Create Windows Service
function Create-Service {
    Write-Step "Step 6: Creating Windows Service"
    
    $nssmExe = Install-NSSM
    
    # Stop and remove existing service if it exists
    $existingService = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Info "Stopping existing service..."
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        Write-Info "Removing existing service..."
        & $nssmExe remove $SERVICE_NAME confirm
        Start-Sleep -Seconds 2
    }
    
    Write-Info "Creating Windows Service: $SERVICE_NAME"
    
    # Install service
    & $nssmExe install $SERVICE_NAME "$INSTALL_DIR\evilginx.exe"
    
    # Configure service parameters
    & $nssmExe set $SERVICE_NAME AppParameters "-p `"$PHISHLETS_DIR`" -t `"$REDIRECTORS_DIR`" -c `"$CONFIG_DIR`""
    & $nssmExe set $SERVICE_NAME AppDirectory "$INSTALL_DIR"
    & $nssmExe set $SERVICE_NAME DisplayName "Evilginx 3.3.1 - Private Dev Edition"
    & $nssmExe set $SERVICE_NAME Description "Evilginx - Advanced phishing framework for authorized security testing"
    & $nssmExe set $SERVICE_NAME Start SERVICE_AUTO_START
    & $nssmExe set $SERVICE_NAME AppStdout "$LOG_DIR\service.log"
    & $nssmExe set $SERVICE_NAME AppStderr "$LOG_DIR\service_error.log"
    & $nssmExe set $SERVICE_NAME AppRotateFiles 1
    & $nssmExe set $SERVICE_NAME AppRotateOnline 1
    & $nssmExe set $SERVICE_NAME AppRotateSeconds 86400
    & $nssmExe set $SERVICE_NAME AppRotateBytes 10485760
    
    Write-Success "Windows Service created: $SERVICE_NAME"
    
    # Set service to start automatically
    Set-Service -Name $SERVICE_NAME -StartupType Automatic
    Write-Success "Service configured for automatic startup"
}

# Create helper scripts
function Create-HelperScripts {
    Write-Step "Step 7: Creating Helper Scripts"
    
    $scriptsDir = "$env:ProgramFiles\Evilginx"
    New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null
    
    # Start script
    @"
@echo off
net start $SERVICE_NAME
sc query $SERVICE_NAME
"@ | Out-File -FilePath "$scriptsDir\evilginx-start.bat" -Encoding ASCII
    
    # Stop script
    @"
@echo off
net stop $SERVICE_NAME
echo Evilginx stopped
"@ | Out-File -FilePath "$scriptsDir\evilginx-stop.bat" -Encoding ASCII
    
    # Restart script
    @"
@echo off
net stop $SERVICE_NAME
timeout /t 2 /nobreak >nul
net start $SERVICE_NAME
sc query $SERVICE_NAME
"@ | Out-File -FilePath "$scriptsDir\evilginx-restart.bat" -Encoding ASCII
    
    # Status script
    @"
@echo off
sc query $SERVICE_NAME
"@ | Out-File -FilePath "$scriptsDir\evilginx-status.bat" -Encoding ASCII
    
    # Logs script
    @"
@echo off
powershell -Command "Get-Content '$LOG_DIR\service.log' -Wait -Tail 50"
"@ | Out-File -FilePath "$scriptsDir\evilginx-logs.bat" -Encoding ASCII
    
    # Console script (interactive mode)
    @"
@echo off
echo Stopping service to run interactively...
net stop $SERVICE_NAME
echo.
echo Starting Evilginx in interactive mode...
echo Press Ctrl+C to stop, then run 'evilginx-start' to resume service mode
echo.
cd /d $INSTALL_DIR
evilginx.exe -p phishlets -t redirectors -c $CONFIG_DIR
"@ | Out-File -FilePath "$scriptsDir\evilginx-console.bat" -Encoding ASCII
    
    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$scriptsDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$scriptsDir", "Machine")
        Write-Success "Helper scripts directory added to PATH"
    }
    
    Write-Success "Helper scripts created in $scriptsDir"
}

# Display completion
function Show-Completion {
    Write-Output ""
    Write-ColorOutput Green "╔═══════════════════════════════════════════════════════════════════╗"
    Write-ColorOutput Green "║                                                                   ║"
    Write-ColorOutput Green "║          ✓ INSTALLATION COMPLETED SUCCESSFULLY!                  ║"
    Write-ColorOutput Green "║                                                                   ║"
    Write-ColorOutput Green "╚═══════════════════════════════════════════════════════════════════╝"
    Write-Output ""
    
    Write-Step "Installation Summary"
    
    Write-ColorOutput Cyan "Installation Details:"
    Write-Output "  • Evilginx Binary:      $INSTALL_DIR\evilginx.exe"
    Write-Output "  • Phishlets Directory:  $PHISHLETS_DIR"
    Write-Output "  • Redirectors Directory: $REDIRECTORS_DIR"
    Write-Output "  • Configuration:        $CONFIG_DIR"
    Write-Output "  • Logs:                 $LOG_DIR"
    Write-Output "  • Windows Service:      $SERVICE_NAME"
    Write-Output ""
    
    Write-ColorOutput Cyan "Firewall Rules (Windows Firewall):"
    Write-Output "  • Port 53/tcp  - DNS (allow)"
    Write-Output "  • Port 53/udp  - DNS (allow)"
    Write-Output "  • Port 80/tcp  - HTTP (allow)"
    Write-Output "  • Port 443/tcp - HTTPS (allow)"
    Write-Output ""
    
    Write-ColorOutput Cyan "Available Commands:"
    Write-Output "  • evilginx-start        - Start Evilginx service"
    Write-Output "  • evilginx-stop         - Stop Evilginx service"
    Write-Output "  • evilginx-restart      - Restart Evilginx service"
    Write-Output "  • evilginx-status       - Check service status"
    Write-Output "  • evilginx-logs         - View live logs"
    Write-Output "  • evilginx-console      - Run interactive console"
    Write-Output ""
    
    Write-ColorOutput Cyan "Windows Service Commands:"
    Write-Output "  • net start $SERVICE_NAME     - Start service"
    Write-Output "  • net stop $SERVICE_NAME      - Stop service"
    Write-Output "  • sc query $SERVICE_NAME      - Check status"
    Write-Output "  • Get-Service $SERVICE_NAME   - PowerShell status"
    Write-Output ""
    
    Write-ColorOutput Yellow "⚠️  IMPORTANT: Next Steps"
    Write-Output ""
    Write-Output "1. Configure Evilginx before starting:"
    Write-Output "   Run: evilginx-console"
    Write-Output ""
    Write-Output "2. In the Evilginx console, configure:"
    Write-Output "   config domain yourdomain.com"
    Write-Output "   config ipv4 external YOUR_PUBLIC_IP"
    Write-Output "   config autocert on"
    Write-Output "   config lure_strategy realistic"
    Write-Output ""
    Write-Output "3. Enable a phishlet:"
    Write-Output "   phishlets hostname o365 login.yourdomain.com"
    Write-Output "   phishlets enable o365"
    Write-Output ""
    Write-Output "4. Create a lure:"
    Write-Output "   lures create o365"
    Write-Output "   lures get-url 0"
    Write-Output ""
    Write-Output "5. Exit console (Ctrl+C) and start service:"
    Write-Output "   evilginx-start"
    Write-Output ""
    
    Write-ColorOutput Yellow "⚠️  SECURITY REMINDERS"
    Write-Output ""
    Write-Output "  • Ensure you have WRITTEN AUTHORIZATION"
    Write-Output "  • Configure Cloudflare DNS for your domain"
    Write-Output "  • Enable advanced features (ML, JA3, Sandbox detection)"
    Write-Output "  • Set up Telegram notifications for monitoring"
    Write-Output "  • Review DEPLOYMENT_GUIDE.md for complete setup"
    Write-Output ""
    
    Write-ColorOutput Green "Documentation:"
    Write-Output "  • Main Guide:           $INSTALL_DIR\DEPLOYMENT_GUIDE.md"
    Write-Output "  • Lure Randomization:   $INSTALL_DIR\LURE_RANDOMIZATION_GUIDE.md"
    Write-Output "  • README:               $INSTALL_DIR\README.md"
    Write-Output ""
    
    Write-ColorOutput Cyan "Quick Start:"
    Write-Output "  1. evilginx-console     # Configure interactively"
    Write-Output "  2. <configure settings> # Set domain, IP, phishlets"
    Write-Output "  3. exit or Ctrl+C       # Exit console"
    Write-Output "  4. evilginx-start       # Start service"
    Write-Output "  5. evilginx-status      # Verify running"
    Write-Output ""
    
    Write-ColorOutput Green "═══════════════════════════════════════════════════════════"
    Write-Output ""
}

# Main installation flow
function Main {
    Show-Banner
    
    # Pre-installation checks
    Test-Administrator
    Confirm-Installation
    
    # Installation steps
    Install-Go
    Build-Evilginx
    Install-Files
    Configure-Firewall
    Create-Service
    Create-HelperScripts
    
    # Completion
    Show-Completion
    
    Write-Success "Installation complete! Review the information above."
}

# Run main installation
try {
    Main
} catch {
    Write-Error "Installation failed: $_"
    Write-Output $_.ScriptStackTrace
    exit 1
}

exit 0

