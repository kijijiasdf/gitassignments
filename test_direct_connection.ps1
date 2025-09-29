# Test Direct Connection to Exchange Online
# This script demonstrates the most reliable connection method for PowerShell 5.1

Write-Host "Direct Exchange Online Connection Test" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host "This test uses the direct connection method that works reliably in PowerShell 5.1" -ForegroundColor Yellow
Write-Host ""

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
Write-Host "Step 3: Attempting direct connection..." -ForegroundColor Yellow
Write-Host "This is the most reliable method for PowerShell 5.1 environments." -ForegroundColor Gray
Write-Host ""

try {
    Write-Host "Running: Connect-ExchangeOnline -ShowBanner:`$false" -ForegroundColor Gray
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "SUCCESS: Connected to Exchange Online!" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Step 4: Testing connection..." -ForegroundColor Yellow
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "SUCCESS: Connected to organization - $($orgConfig.DisplayName)" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "CONNECTION TEST PASSED!" -ForegroundColor Green
    Write-Host "You can now run your Exchange Online scripts." -ForegroundColor Cyan
    
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
    Write-Host "To disconnect when finished, run:" -ForegroundColor Yellow
    Write-Host "Disconnect-ExchangeOnline -Confirm:`$false" -ForegroundColor Gray
    
} catch {
    Write-Error "FAILED: Could not connect to Exchange Online"
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "ALTERNATIVE APPROACH:" -ForegroundColor Yellow
    Write-Host "1. Close this script" -ForegroundColor Gray
    Write-Host "2. In your PowerShell session, manually run:" -ForegroundColor Gray
    Write-Host "   Connect-ExchangeOnline -ShowBanner:`$false" -ForegroundColor Cyan
    Write-Host "3. If that fails, try with your UPN:" -ForegroundColor Gray
    Write-Host "   Connect-ExchangeOnline -UserPrincipalName 'your-email@domain.com' -ShowBanner:`$false" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Test completed." -ForegroundColor Cyan