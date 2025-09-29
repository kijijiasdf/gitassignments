# Test Exchange Online Connection and Basic Role Retrieval
Write-Host "Exchange Online Connection and Basic Role Test" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

try {
    Write-Host "Checking for Exchange Online module..." -ForegroundColor Yellow
    Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
    Write-Host "Module imported successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Exchange Online module: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "Checking connection status..." -ForegroundColor Yellow
    $connection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($connection) {
        Write-Host "Connected to Exchange Online" -ForegroundColor Green
        Write-Host "Organization: $($connection.OrganizationName)" -ForegroundColor Gray
        Write-Host "User: $($connection.UserPrincipalName)" -ForegroundColor Gray
    } else {
        Write-Host "Not connected to Exchange Online" -ForegroundColor Yellow
        Write-Host "Please connect first using Connect-ExchangeOnline" -ForegroundColor Gray
        exit 1
    }
} catch {
    Write-Error "Failed to check connection status: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "Testing basic role assignment retrieval..." -ForegroundColor Yellow
    $assignments = Get-ManagementRoleAssignment -ResultSize 5 -ErrorAction Stop
    Write-Host "Successfully retrieved $($assignments.Count) role assignments" -ForegroundColor Green
    
    Write-Host "`nSample assignments:" -ForegroundColor Yellow
    $assignments | Format-Table -Property Name, Role, RoleAssigneeName, RoleAssigneeType -AutoSize
    
    Write-Host "Testing role details retrieval..." -ForegroundColor Yellow
    $roleDetails = Get-ManagementRole -Identity $assignments[0].Role -ErrorAction Stop
    Write-Host "Successfully retrieved role details for '$($roleDetails.Name)'" -ForegroundColor Green
    Write-Host "Role description: $($roleDetails.Description)" -ForegroundColor Gray
    
    Write-Host "`nConnection and basic functionality test PASSED!" -ForegroundColor Green
} catch {
    Write-Error "Failed basic functionality test: $($_.Exception.Message)"
    exit 1
}

Write-Host "`nTest completed successfully!" -ForegroundColor Cyan
Write-Host "You can now run the ExchangeOnline-RoleAssignments.ps1 script." -ForegroundColor Green