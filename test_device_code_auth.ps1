# Test script for Exchange Online authentication methods (PowerShell 5.1 Compatible)
Write-Host "Testing Exchange Online Authentication Methods (PowerShell 5.1)" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "Note: Device parameter only available in PowerShell 7+. Using PowerShell 5.1 compatible methods." -ForegroundColor Yellow
Write-Host ""

try {
    # Import Exchange Online module
    Write-Host "Importing Exchange Online module..." -ForegroundColor Yellow
    Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
    Write-Host "Exchange Online module imported successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Exchange Online module: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "Checking for existing connections..." -ForegroundColor Yellow
    $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    
    if ($existingConnection) {
        Write-Host "Found existing connection. Disconnecting first..." -ForegroundColor Yellow
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    
    Write-Host "Testing UserPrincipalName authentication method..." -ForegroundColor Yellow
    Write-Host "You will be prompted to sign in with your credentials in the browser." -ForegroundColor Cyan
    Write-Host "Important: MFA may be required for your account due to 2025 changes." -ForegroundColor Cyan
    Write-Host "Press Enter to continue with authentication..." -ForegroundColor Gray
    Read-Host
    
    # Use UserPrincipalName authentication which is compatible with PowerShell 5.1
    $userPrincipalName = Read-Host "Enter your User Principal Name (email address)"
    Connect-ExchangeOnline -UserPrincipalName $userPrincipalName -ShowBanner:$false -ErrorAction Stop
    
    Write-Host "Successfully connected to Exchange Online!" -ForegroundColor Green
    
    # Test the connection
    Write-Host "Testing connection..." -ForegroundColor Yellow
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "Organization: $($orgConfig.Name)" -ForegroundColor Green
    
    Write-Host "UserPrincipalName authentication test completed successfully!" -ForegroundColor Green
    
    # Disconnect for cleanup
    Write-Host "Disconnecting..." -ForegroundColor Yellow
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    
} catch {
    Write-Error "UserPrincipalName authentication test failed: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "For PowerShell 5.1, try these alternatives:" -ForegroundColor Yellow
    Write-Host "1. Standard connection: Connect-ExchangeOnline -ShowBanner:`$false" -ForegroundColor Gray
    Write-Host "2. With specific organization: Connect-ExchangeOnline -Organization 'yourdomain.onmicrosoft.com' -ShowBanner:`$false" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Due to 2025 authentication changes, ensure:" -ForegroundColor Yellow
    Write-Host "1. MFA is enabled and configured for your account" -ForegroundColor Gray
    Write-Host "2. You're using the latest ExchangeOnlineManagement module" -ForegroundColor Gray
    Write-Host "3. Your account has the necessary Exchange Online permissions" -ForegroundColor Gray
    exit 1
}

Write-Host "Test completed!" -ForegroundColor Green