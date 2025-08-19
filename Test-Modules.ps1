<#
.SYNOPSIS
    Test script to verify Microsoft Graph module installation
#>

Write-Host "Testing Microsoft Graph module installation..." -ForegroundColor Green

# Check PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "PowerShell version: $psVersion" -ForegroundColor Cyan

# Check execution policy
$executionPolicy = Get-ExecutionPolicy
Write-Host "Execution policy: $executionPolicy" -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as Administrator: $isAdmin" -ForegroundColor Cyan

# Check available repositories
Write-Host "`nAvailable repositories:" -ForegroundColor Yellow
Get-PSRepository | Format-Table -AutoSize

# Test module availability
$modules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')

foreach ($module in $modules) {
    Write-Host "`nTesting module: $module" -ForegroundColor Yellow
    
    # Check if available in repositories
    try {
        $available = Find-Module -Name $module -ErrorAction Stop
        if ($available) {
            Write-Host "✓ Module $module is available in repositories" -ForegroundColor Green
            Write-Host "  Version: $($available.Version)" -ForegroundColor Gray
            Write-Host "  Repository: $($available.Repository)" -ForegroundColor Gray
        }
        else {
            Write-Host "✗ Module $module not found in repositories" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "✗ Error checking module $module`: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Check if already installed
    $installed = Get-Module -ListAvailable $module
    if ($installed) {
        Write-Host "✓ Module $module is already installed" -ForegroundColor Green
        Write-Host "  Version: $($installed.Version)" -ForegroundColor Gray
    }
    else {
        Write-Host "✗ Module $module is not installed" -ForegroundColor Yellow
    }
}

Write-Host "`nTest completed!" -ForegroundColor Green