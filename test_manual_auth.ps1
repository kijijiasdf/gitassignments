# Simple test script for manual authentication
Write-Host "Manual Authentication Test" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

Write-Host "`n1. Testing Microsoft Graph authentication..." -ForegroundColor Yellow
Write-Host "Executing: Connect-MgGraph -TenantId '75bf4402-ab2f-47d4-82cf-c9c3cf971dcc' -UseDeviceCode" -ForegroundColor Gray
Write-Host "Watch for the device code prompt below:" -ForegroundColor Gray

try {
    Connect-MgGraph -TenantId '75bf4402-ab2f-47d4-82cf-c9c3cf971dcc' -UseDeviceCode
    $context = Get-MgContext
    Write-Host "SUCCESS: Connected to tenant $($context.TenantId)" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n2. Testing Exchange Online connection..." -ForegroundColor Yellow
try {
    Connect-ExchangeOnline -Organization '75bf4402-ab2f-47d4-82cf-c9c3cf971dcc' -ShowBanner:$false
    $org = Get-OrganizationConfig
    Write-Host "SUCCESS: Connected to Exchange Online - $($org.DisplayName)" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n3. Cleaning up..." -ForegroundColor Yellow
try {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Write-Host "SUCCESS: Connections cleaned up" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Some cleanup errors occurred" -ForegroundColor Yellow
}

Write-Host "`nManual authentication test completed successfully!" -ForegroundColor Cyan
Write-Host "You can now run your audit scripts with pre-authenticated sessions." -ForegroundColor Gray