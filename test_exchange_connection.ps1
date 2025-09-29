# Test script for Exchange Online connection
Write-Host "Testing Exchange Online connection..." -ForegroundColor Yellow

try {
    # Import Exchange Online module
    Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
    Write-Host "Exchange Online module imported successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Exchange Online module: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "Attempting to connect to Exchange Online..." -ForegroundColor Cyan
    
    # Use the same connection approach as our main script
    $connectParams = @{
        ShowBanner = $false
        ErrorAction = 'Stop'
    }
    
    Connect-ExchangeOnline @connectParams
    
    Write-Host "Successfully connected to Exchange Online!" -ForegroundColor Green
    
    # Test a simple command
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "Organization Name: $($orgConfig.Name)" -ForegroundColor Green
    
    # Disconnect
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Disconnected from Exchange Online" -ForegroundColor Gray
    
} catch {
    Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
    exit 1
}

Write-Host "Test completed successfully!" -ForegroundColor Green