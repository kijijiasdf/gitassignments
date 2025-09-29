# Pre-authentication script for Exchange Online
# Updated for 2025 authentication changes (PowerShell 5.1 Compatible)
# Run this script first to establish a connection, then run the main audit script

Write-Host "Exchange Online Pre-Authentication Script (2025)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Note: Microsoft has made significant authentication changes in 2025" -ForegroundColor Yellow
Write-Host "This script handles the new requirements for PowerShell 5.1" -ForegroundColor Yellow
Write-Host ""

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "PowerShell Version: $psVersion" -ForegroundColor Yellow

# PowerShell 5.1 specific warning
if ($psVersion.Major -eq 5) {
    Write-Host "INFO: You are using PowerShell 5.1 which has known compatibility issues with Exchange Online." -ForegroundColor Yellow
    Write-Host "We will apply specific workarounds for these issues." -ForegroundColor Gray
}

try {
    Write-Host "Checking for Exchange Online module..." -ForegroundColor Yellow
    
    # Check if Exchange Online module is installed
    $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement
    if (-not $exoModule) {
        Write-Host "Installing Exchange Online module..." -ForegroundColor Yellow
        Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
    } else {
        Write-Host "Exchange Online module version(s) found:" -ForegroundColor Green
        $exoModule | ForEach-Object { Write-Host "  - $($_.Version)" -ForegroundColor Gray }
    }
    
    Write-Host "Importing Exchange Online module..." -ForegroundColor Yellow
    Import-Module ExchangeOnlineManagement -Force
    
    Write-Host "Checking for existing Exchange Online connection..." -ForegroundColor Yellow
    
    # Check if already connected
    $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($existingConnection) {
        Write-Host "Already connected to Exchange Online" -ForegroundColor Green
        Write-Host "Connection state: $($existingConnection.State)" -ForegroundColor Gray
        Write-Host "Organization: $($existingConnection.OrganizationName)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "You can now run the ExchangeOnline-RoleAssignments.ps1 script." -ForegroundColor Green
        return
    }
    
    Write-Host "No existing connection found. Connecting to Exchange Online..." -ForegroundColor Yellow
    
    # Disconnect any existing session first
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    
    # PowerShell 5.1 specific workarounds
    if ($psVersion.Major -eq 5) {
        Write-Host "Applying PowerShell 5.1 specific workarounds..." -ForegroundColor Yellow
        
        # Workaround 1: Set specific .NET culture settings
        [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture
        
        # Workaround 2: Use DisableWAM parameter to avoid window handle issues
        Write-Host "Attempting connection with DisableWAM parameter..." -ForegroundColor Gray
        try {
            Connect-ExchangeOnline -ShowBanner:$false -DisableWAM $true -ErrorAction Stop
            Write-Host "Successfully connected using PowerShell 5.1 workaround!" -ForegroundColor Green
        } catch {
            Write-Host "First workaround failed, trying alternative..." -ForegroundColor Yellow
            
            # Workaround 3: Try with UserPrincipalName and DisableWAM
            $upn = Read-Host "Enter your User Principal Name (email address)"
            Connect-ExchangeOnline -UserPrincipalName $upn -ShowBanner:$false -DisableWAM $true -ErrorAction Stop
            Write-Host "Successfully connected using alternative PowerShell 5.1 workaround!" -ForegroundColor Green
        }
    } else {
        # For PowerShell 7+, use standard methods
        Write-Host "Attempting standard connection method..." -ForegroundColor Yellow
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "Successfully connected!" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "You can now run the ExchangeOnline-RoleAssignments.ps1 script." -ForegroundColor Green
    Write-Host "The connection will be reused, so you won't need to authenticate again." -ForegroundColor Green
    
    # Test the connection
    Write-Host "Testing connection..." -ForegroundColor Yellow
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "Connected to organization: $($orgConfig.DisplayName)" -ForegroundColor Green
    
    # Show connection details
    $connectionInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($connectionInfo) {
        Write-Host "Connection Details:" -ForegroundColor Yellow
        Write-Host "  State: $($connectionInfo.State)" -ForegroundColor Gray
        Write-Host "  Organization: $($connectionInfo.OrganizationName)" -ForegroundColor Gray
        Write-Host "  User: $($connectionInfo.UserPrincipalName)" -ForegroundColor Gray
        Write-Host "  Authentication Type: $($connectionInfo.AuthenticationType)" -ForegroundColor Gray
    }
    
} catch [System.Management.Automation.CmdletInvocationException] {
    # Handle the specific window handle error and other 2025 authentication issues
    if ($_.Exception.Message -like "*window handle*" -or $_.Exception.Message -like "*WAM*" -or $_.Exception.Message -like "*MFA*") {
        Write-Warning "Encountered persistent authentication compatibility issue."
        Write-Warning "This is a known issue with PowerShell 5.1 and Exchange Online module."
        
        Write-Host ""
        Write-Host "DIRECT SOLUTION (Recommended):" -ForegroundColor Yellow
        Write-Host "1. Close this script" -ForegroundColor Gray
        Write-Host "2. In your current PowerShell session, manually run one of these commands:" -ForegroundColor Gray
        Write-Host "   Option A: Connect-ExchangeOnline -ShowBanner:`$false -DisableWAM `$true" -ForegroundColor Cyan
        Write-Host "   Option B: Connect-ExchangeOnline -UserPrincipalName 'your-email@domain.com' -ShowBanner:`$false -DisableWAM `$true" -ForegroundColor Cyan
        Write-Host "3. After successful connection, run the ExchangeOnline-RoleAssignments.ps1 script" -ForegroundColor Gray
        Write-Host ""
        Write-Host "ALTERNATIVE: Run the powershell_51_exchange_connect.ps1 script" -ForegroundColor Yellow
        Write-Host "This script uses specialized workarounds for PowerShell 5.1 environments." -ForegroundColor Gray
        Write-Host ""
        Write-Host "BEST OPTION: Use PowerShell 7 instead of PowerShell 5.1 for Exchange Online connections" -ForegroundColor Green
        
    } else {
        Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
        
        Write-Host ""
        Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "1. Ensure you have the ExchangeOnlineManagement module installed" -ForegroundColor Gray
        Write-Host "2. Try running PowerShell as Administrator" -ForegroundColor Gray
        Write-Host "3. Ensure you have internet connectivity" -ForegroundColor Gray
        Write-Host "4. Check that your account has the necessary permissions" -ForegroundColor Gray
        Write-Host "5. If using MFA, ensure it's configured properly" -ForegroundColor Gray
    }
} catch {
    Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
    
    Write-Host ""
    Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
    Write-Host "1. Ensure you have the ExchangeOnlineManagement module installed" -ForegroundColor Gray
    Write-Host "2. Try running PowerShell as Administrator" -ForegroundColor Gray
    Write-Host "3. Ensure you have internet connectivity" -ForegroundColor Gray
    Write-Host "4. Check that your account has the necessary permissions" -ForegroundColor Gray
    Write-Host "5. If using MFA, ensure it's configured properly" -ForegroundColor Gray
}