# Exchange Online Connection Diagnostic Script (2025 Updated - PowerShell 5.1 Compatible)
Write-Host "Exchange Online Connection Diagnostic (2025 - PowerShell 5.1)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Note: Microsoft has made significant authentication changes in 2025" -ForegroundColor Yellow
Write-Host "This script is compatible with PowerShell 5.1" -ForegroundColor Yellow
Write-Host ""

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "PowerShell Version: $psVersion" -ForegroundColor Yellow

try {
    Write-Host "Checking for Exchange Online module..." -ForegroundColor Yellow
    
    # Check if Exchange Online module is installed
    $exoModule = Get-Module -ListAvailable -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
    if ($exoModule) {
        Write-Host "Exchange Online module found:" -ForegroundColor Green
        $exoModule | ForEach-Object { Write-Host "  - Version $($_.Version) in $($_.ModuleBase)" -ForegroundColor Gray }
    } else {
        Write-Host "Exchange Online module not found" -ForegroundColor Red
        Write-Host "Please install it with: Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "Importing Exchange Online module..." -ForegroundColor Yellow
    Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
    Write-Host "Module imported successfully" -ForegroundColor Green
    
    Write-Host "Checking for existing connections..." -ForegroundColor Yellow
    $connections = Get-ConnectionInformation -ErrorAction SilentlyContinue
    
    if ($connections) {
        Write-Host "Active Exchange Online connections found:" -ForegroundColor Green
        $connections | ForEach-Object {
            Write-Host "  - State: $($_.State)" -ForegroundColor Gray
            Write-Host "  - Organization: $($_.OrganizationName)" -ForegroundColor Gray
            Write-Host "  - User: $($_.UserPrincipalName)" -ForegroundColor Gray
            Write-Host "  - Authentication: $($_.AuthenticationType)" -ForegroundColor Gray
        }
    } else {
        Write-Host "No active Exchange Online connections found" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Connection Diagnostic Summary:" -ForegroundColor Yellow
    Write-Host "1. PowerShell version: $psVersion" -ForegroundColor Gray
    Write-Host "2. Exchange Online module: Installed" -ForegroundColor Gray
    Write-Host "3. Active connections: $(if($connections) { 'Yes' } else { 'None' })" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To connect to Exchange Online in PowerShell 5.1, use one of these methods:" -ForegroundColor Yellow
    Write-Host "  Standard: Connect-ExchangeOnline -ShowBanner:`$false" -ForegroundColor Gray
    Write-Host "  With UPN: Connect-ExchangeOnline -UserPrincipalName 'user@domain.com' -ShowBanner:`$false" -ForegroundColor Gray
    Write-Host "  With Org: Connect-ExchangeOnline -Organization 'yourdomain.onmicrosoft.com' -ShowBanner:`$false" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Note: Device authentication requires PowerShell 7+ (you are using PowerShell $psVersion)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Due to 2025 authentication changes:" -ForegroundColor Cyan
    Write-Host "1. MFA may be required for your account" -ForegroundColor Gray
    Write-Host "2. Legacy authentication methods are deprecated" -ForegroundColor Gray
    Write-Host "3. ROPC (username/password) authentication is deprecated" -ForegroundColor Gray
    Write-Host ""
    Write-Host "If you encounter 'window handle' errors in PowerShell 5.1:" -ForegroundColor Yellow
    Write-Host "1. Use UserPrincipalName authentication: Connect-ExchangeOnline -UserPrincipalName 'user@domain.com' -ShowBanner:`$false" -ForegroundColor Gray
    Write-Host "2. Ensure you're using the -ShowBanner:`$false parameter" -ForegroundColor Gray
    Write-Host "3. Try disconnecting existing sessions first" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Authentication Process:" -ForegroundColor Cyan
    Write-Host "1. Run one of the connection commands above" -ForegroundColor Gray
    Write-Host "2. A browser window will open for authentication" -ForegroundColor Gray
    Write-Host "3. Sign in with your credentials (MFA may be required)" -ForegroundColor Gray
    Write-Host "4. Grant the necessary permissions" -ForegroundColor Gray
    Write-Host ""
    Write-Host "For automation, consider app-based authentication with certificates." -ForegroundColor Cyan
    
} catch {
    Write-Error "Diagnostic failed: $($_.Exception.Message)"
    exit 1
}

Write-Host ""
Write-Host "Diagnostic completed successfully!" -ForegroundColor Green
Write-Host "Refer to EXCHANGE_ONLINE_AUTHENTICATION_2025.md for detailed information about 2025 changes." -ForegroundColor Cyan