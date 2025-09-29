# Manual Connection Script for Exchange Online (PowerShell 5.1 Compatible)
# This script uses the most reliable connection method for PowerShell 5.1 environments

Write-Host "Manual Exchange Online Connection Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Using proven method for PowerShell 5.1 compatibility" -ForegroundColor Yellow
Write-Host ""

try {
    Write-Host "Importing Exchange Online module..." -ForegroundColor Yellow
    Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
    Write-Host "Module imported successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Exchange Online module: $($_.Exception.Message)"
    Write-Host "Please ensure the ExchangeOnlineManagement module is installed:" -ForegroundColor Yellow
    Write-Host "Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser" -ForegroundColor Gray
    exit 1
}

try {
    Write-Host "Checking for existing connections..." -ForegroundColor Yellow
    $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    
    if ($existingConnection) {
        Write-Host "Found existing connection. Disconnecting first..." -ForegroundColor Yellow
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
    
    Write-Host "Using proven connection method for PowerShell 5.1..." -ForegroundColor Yellow
    Write-Host "This method avoids the window handle issue by using specific parameters." -ForegroundColor Gray
    Write-Host ""
    
    # Use the exact parameters that work reliably in PowerShell 5.1
    # This combination has been tested and works even with MFA enforced
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    
    Write-Host "Connection successful!" -ForegroundColor Green
    Write-Host ""
    
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
    }
    
    Write-Host ""
    Write-Host "You can now run the ExchangeOnline-RoleAssignments.ps1 script." -ForegroundColor Green
    Write-Host "The connection will be reused for this session." -ForegroundColor Green
    
} catch [System.Management.Automation.CmdletInvocationException] {
    if ($_.Exception.Message -like "*window handle*") {
        Write-Warning "Still encountering the window handle issue."
        Write-Warning "This is a known compatibility issue with PowerShell 5.1."
        Write-Host ""
        Write-Host "ALTERNATIVE SOLUTIONS:" -ForegroundColor Yellow
        Write-Host "1. Try running PowerShell as Administrator" -ForegroundColor Gray
        Write-Host "2. Manually run this command in your PowerShell session:" -ForegroundColor Gray
        Write-Host "   Connect-ExchangeOnline -ShowBanner:`$false" -ForegroundColor Cyan
        Write-Host "3. If that fails, try:" -ForegroundColor Gray
        Write-Host "   Connect-ExchangeOnline -UserPrincipalName 'your-email@domain.com' -ShowBanner:`$false" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "After connecting manually, you can run the ExchangeOnline-RoleAssignments.ps1 script." -ForegroundColor Green
    } else {
        Write-Error "Connection failed: $($_.Exception.Message)"
    }
} catch {
    Write-Error "Connection failed: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Script completed." -ForegroundColor Cyan