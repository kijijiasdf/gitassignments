# Test script to compare authentication flows
Write-Host "Testing different authentication flows..." -ForegroundColor Yellow

Write-Host "`n1. Testing Connect-MgGraph WITHOUT -UseDeviceCode parameter:" -ForegroundColor Cyan
try {
    Write-Host "Executing: Connect-MgGraph -TenantId 75bf4402-ab2f-47d4-82cf-c9c3cf971dcc" -ForegroundColor Gray
    Connect-MgGraph -TenantId 75bf4402-ab2f-47d4-82cf-c9c3cf971dcc
    $context = Get-MgContext
    Write-Host "Successfully connected to tenant: $($context.TenantId)" -ForegroundColor Green
    Disconnect-MgGraph -ErrorAction SilentlyContinue
} catch {
    Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n2. Testing Connect-MgGraph WITH -UseDeviceCode parameter:" -ForegroundColor Cyan
try {
    Write-Host "Executing: Connect-MgGraph -TenantId 75bf4402-ab2f-47d4-82cf-c9c3cf971dcc -UseDeviceCode" -ForegroundColor Gray
    Write-Host "You SHOULD see a device code prompt in the console:" -ForegroundColor Gray
    Connect-MgGraph -TenantId 75bf4402-ab2f-47d4-82cf-c9c3cf971dcc -UseDeviceCode
    $context = Get-MgContext
    Write-Host "Successfully connected to tenant: $($context.TenantId)" -ForegroundColor Green
    Disconnect-MgGraph -ErrorAction SilentlyContinue
} catch {
    Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nTest complete." -ForegroundColor Yellow