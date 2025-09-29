# PowerShell 5.1 Specific Exchange Online Connection Workaround
# This script uses specialized techniques to avoid the window handle error in PowerShell 5.1

Write-Host "PowerShell 5.1 Exchange Online Connection Workaround" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "Using specialized techniques for PowerShell 5.1 compatibility" -ForegroundColor Yellow
Write-Host ""

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "PowerShell Version: $psVersion" -ForegroundColor Yellow

if ($psVersion.Major -gt 5) {
    Write-Host "WARNING: You are not using PowerShell 5.1. This script is designed for PowerShell 5.1." -ForegroundColor Yellow
    $continue = Read-Host "Do you want to continue anyway? (Y/N)"
    if ($continue -ne 'Y' -and $continue -ne 'y') {
        exit
    }
}

try {
    Write-Host "Step 1: Importing Exchange Online module..." -ForegroundColor Yellow
    Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
    Write-Host "SUCCESS: Module imported" -ForegroundColor Green
} catch {
    Write-Error "FAILED: Could not import Exchange Online module"
    Write-Host "Please install it with: Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser" -ForegroundColor Gray
    exit 1
}

try {
    Write-Host "Step 2: Checking for existing connections..." -ForegroundColor Yellow
    $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    
    if ($existingConnection) {
        Write-Host "FOUND: Existing connection" -ForegroundColor Yellow
        Write-Host "Disconnecting first..." -ForegroundColor Gray
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    } else {
        Write-Host "No existing connections found" -ForegroundColor Green
    }
} catch {
    Write-Host "INFO: No existing connections to check" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Step 3: Preparing PowerShell 5.1 specific connection workaround..." -ForegroundColor Yellow

# PowerShell 5.1 specific workaround techniques
try {
    Write-Host "Applying PowerShell 5.1 window handle workaround..." -ForegroundColor Gray
    
    # Workaround 1: Set specific .NET culture settings
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture
    
    # Workaround 2: Disable WAM (Web Account Manager) which causes issues in PowerShell 5.1
    $connectParams = @{
        ShowBanner = $false
        DisableWAM = $true
        ErrorAction = 'Stop'
    }
    
    Write-Host "Using DisableWAM parameter to avoid window handle issues..." -ForegroundColor Gray
    Write-Host "Running: Connect-ExchangeOnline with DisableWAM parameter" -ForegroundColor Gray
    
    Connect-ExchangeOnline @connectParams
    
    Write-Host "SUCCESS: Connected to Exchange Online using PowerShell 5.1 workaround!" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Step 4: Testing connection..." -ForegroundColor Yellow
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "SUCCESS: Connected to organization - $($orgConfig.DisplayName)" -ForegroundColor Green
    
    # Show connection info
    $connectionInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($connectionInfo) {
        Write-Host ""
        Write-Host "Connection Information:" -ForegroundColor Yellow
        Write-Host "  State: $($connectionInfo.State)" -ForegroundColor Gray
        Write-Host "  Organization: $($connectionInfo.OrganizationName)" -ForegroundColor Gray
        Write-Host "  User: $($connectionInfo.UserPrincipalName)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "WORKAROUND SUCCESSFUL!" -ForegroundColor Green
    Write-Host "You can now run your Exchange Online scripts." -ForegroundColor Cyan
    Write-Host "The connection will persist for this PowerShell session." -ForegroundColor Gray
    
} catch [System.Management.Automation.CmdletInvocationException] {
    if ($_.Exception.Message -like "*window handle*") {
        Write-Warning "Window handle error still occurring. Trying alternative PowerShell 5.1 workaround..."
        
        try {
            # Alternative workaround: Use specific parameter combinations
            Write-Host "Trying alternative parameter combination..." -ForegroundColor Yellow
            
            # Workaround 3: Use UserPrincipalName with DisableWAM
            $upn = Read-Host "Enter your User Principal Name (email address)"
            
            $connectParamsAlt = @{
                UserPrincipalName = $upn
                ShowBanner = $false
                DisableWAM = $true
                ErrorAction = 'Stop'
            }
            
            Write-Host "Running alternative connection method..." -ForegroundColor Gray
            Connect-ExchangeOnline @connectParamsAlt
            
            Write-Host "SUCCESS: Connected using alternative PowerShell 5.1 workaround!" -ForegroundColor Green
            
            # Test connection
            $orgConfig = Get-OrganizationConfig -ErrorAction Stop
            Write-Host "SUCCESS: Connected to organization - $($orgConfig.DisplayName)" -ForegroundColor Green
            
        } catch {
            Write-Error "FAILED: All PowerShell 5.1 workarounds failed"
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host ""
            Write-Host "FINAL RECOMMENDATION:" -ForegroundColor Yellow
            Write-Host "1. Use PowerShell 7 instead of PowerShell 5.1 for Exchange Online connections" -ForegroundColor Gray
            Write-Host "2. Or manually run in your PowerShell 5.1 session:" -ForegroundColor Gray
            Write-Host "   Connect-ExchangeOnline -ShowBanner:`$false -DisableWAM `$true" -ForegroundColor Cyan
        }
    } else {
        Write-Error "Connection failed with different error: $($_.Exception.Message)"
    }
} catch {
    Write-Error "FAILED: Could not connect to Exchange Online"
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Workaround script completed." -ForegroundColor Cyan