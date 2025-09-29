#Requires -Version 5.1
<#
.SYNOPSIS
    Test script to validate permissions for Exchange Online role assignment audit scripts
    
.DESCRIPTION
    This script validates that the current user has the necessary permissions to run
    the Exchange Online human access and non-human access audit scripts.
    
.PARAMETER TestHumanAccess
    Test permissions required for Audit-ExchangeOnlineHumanAccess.ps1
    
.PARAMETER TestNonHumanAccess
    Test permissions required for Audit-ExchangeOnlineNonHumanAccess.ps1
    
.PARAMETER TestAll
    Test permissions for both audit scripts
    
.PARAMETER TenantId
    Azure Tenant ID to test permissions against
    
.EXAMPLE
    .\Test-ExchangeOnlinePermissions.ps1 -TestAll
    
.EXAMPLE
    .\Test-ExchangeOnlinePermissions.ps1 -TestHumanAccess -TenantId "12345678-1234-1234-1234-123456789012"
    
.NOTES
    Author: Azure Audit Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$TestHumanAccess,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestNonHumanAccess,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestAll,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

#region Helper Functions
function Write-TestResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestName,
        
        [Parameter(Mandatory = $true)]
        [bool]$Success,
        
        [Parameter(Mandatory = $false)]
        [string]$ErrorMessage = "",
        
        [Parameter(Mandatory = $false)]
        [string]$Recommendation = ""
    )
    
    $status = if ($Success) { "✅ PASS" } else { "❌ FAIL" }
    $color = if ($Success) { "Green" } else { "Red" }
    
    Write-Host "$status - $TestName" -ForegroundColor $color
    
    if (-not $Success -and $ErrorMessage) {
        Write-Host "   Error: $ErrorMessage" -ForegroundColor Yellow
    }
    
    if (-not $Success -and $Recommendation) {
        Write-Host "   Recommendation: $Recommendation" -ForegroundColor Cyan
    }
    
    return $Success
}

function Test-GraphConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    
    try {
        if ($TenantId) {
            $context = Get-MgContext
            if (-not $context -or $context.TenantId -ne $TenantId) {
                Connect-MgGraph -TenantId $TenantId -Scopes @("Directory.Read.All") -ErrorAction Stop
            }
        } else {
            $context = Get-MgContext
            if (-not $context) {
                Connect-MgGraph -Scopes @("Directory.Read.All") -ErrorAction Stop
            }
        }
        return $true
    }
    catch {
        throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    }
}

function Test-ExchangeOnlineConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    
    try {
        $existingSession = Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened" }
        
        if (-not $existingSession) {
            if ($TenantId) {
                Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false -ErrorAction Stop
            } else {
                Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            }
        }
        return $true
    }
    catch {
        throw "Failed to connect to Exchange Online: $($_.Exception.Message)"
    }
}
#endregion

#region Permission Tests
function Test-MicrosoftGraphPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredScopes
    )
    
    $results = @()
    
    # Test Directory.Read.All
    if ($RequiredScopes -contains "Directory.Read.All") {
        try {
            Get-MgUser -Top 1 -ErrorAction Stop | Out-Null
            $results += Write-TestResult -TestName "Microsoft Graph - Directory.Read.All" -Success $true
        }
        catch {
            $results += Write-TestResult -TestName "Microsoft Graph - Directory.Read.All" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Grant Directory.Read.All permission to your application"
        }
    }
    
    # Test RoleManagement.Read.All
    if ($RequiredScopes -contains "RoleManagement.Read.All") {
        try {
            Get-MgDirectoryRole -Top 1 -ErrorAction Stop | Out-Null
            $results += Write-TestResult -TestName "Microsoft Graph - RoleManagement.Read.All" -Success $true
        }
        catch {
            $results += Write-TestResult -TestName "Microsoft Graph - RoleManagement.Read.All" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Grant RoleManagement.Read.All permission to your application"
        }
    }
    
    # Test PrivilegedAccess.Read.AzureAD
    if ($RequiredScopes -contains "PrivilegedAccess.Read.AzureAD") {
        try {
            Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Top 1 -ErrorAction Stop | Out-Null
            $results += Write-TestResult -TestName "Microsoft Graph - PrivilegedAccess.Read.AzureAD" -Success $true
        }
        catch {
            $results += Write-TestResult -TestName "Microsoft Graph - PrivilegedAccess.Read.AzureAD" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Grant PrivilegedAccess.Read.AzureAD permission or ensure PIM is enabled"
        }
    }
    
    # Test Application.Read.All
    if ($RequiredScopes -contains "Application.Read.All") {
        try {
            Get-MgApplication -Top 1 -ErrorAction Stop | Out-Null
            $results += Write-TestResult -TestName "Microsoft Graph - Application.Read.All" -Success $true
        }
        catch {
            $results += Write-TestResult -TestName "Microsoft Graph - Application.Read.All" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Grant Application.Read.All permission to your application"
        }
    }
    
    # Test AppRoleAssignment.Read.All
    if ($RequiredScopes -contains "AppRoleAssignment.Read.All") {
        try {
            Get-MgServicePrincipal -Top 1 -Property 'AppRoleAssignments' -ErrorAction Stop | Out-Null
            $results += Write-TestResult -TestName "Microsoft Graph - AppRoleAssignment.Read.All" -Success $true
        }
        catch {
            $results += Write-TestResult -TestName "Microsoft Graph - AppRoleAssignment.Read.All" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Grant AppRoleAssignment.Read.All permission to your application"
        }
    }
    
    return $results
}

function Test-ExchangeOnlinePermissions {
    [CmdletBinding()]
    param()
    
    $results = @()
    
    # Test basic Exchange Online connectivity
    try {
        Get-OrganizationConfig -ErrorAction Stop | Out-Null
        $results += Write-TestResult -TestName "Exchange Online - Basic Connectivity" -Success $true
    }
    catch {
        $results += Write-TestResult -TestName "Exchange Online - Basic Connectivity" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Ensure you have Exchange Online access and proper licensing"
    }
    
    # Test Management Role Assignment access
    try {
        Get-ManagementRoleAssignment -ResultSize 1 -ErrorAction Stop | Out-Null
        $results += Write-TestResult -TestName "Exchange Online - Management Role Assignments" -Success $true
    }
    catch {
        $results += Write-TestResult -TestName "Exchange Online - Management Role Assignments" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Ensure you have View-Only Organization Management role or higher"
    }
    
    # Test Management Role access
    try {
        Get-ManagementRole -ResultSize 1 -ErrorAction Stop | Out-Null
        $results += Write-TestResult -TestName "Exchange Online - Management Roles" -Success $true
    }
    catch {
        $results += Write-TestResult -TestName "Exchange Online - Management Roles" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Ensure you have View-Only Organization Management role or higher"
    }
    
    # Test Application Access Policy access
    try {
        Get-ApplicationAccessPolicy -ErrorAction Stop | Out-Null
        $results += Write-TestResult -TestName "Exchange Online - Application Access Policies" -Success $true
    }
    catch {
        $results += Write-TestResult -TestName "Exchange Online - Application Access Policies" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "This is normal if no Application Access Policies exist or if you lack sufficient permissions"
    }
    
    return $results
}

function Test-HumanAccessPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    
    Write-Host "`n🔍 Testing permissions for Exchange Online Human Access Audit Script..." -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    $allResults = @()
    $requiredGraphScopes = @("Directory.Read.All", "RoleManagement.Read.All", "PrivilegedAccess.Read.AzureAD")
    
    # Test Microsoft Graph connection
    try {
        Test-GraphConnection -TenantId $TenantId
        $allResults += Write-TestResult -TestName "Microsoft Graph Connection" -Success $true
    }
    catch {
        $allResults += Write-TestResult -TestName "Microsoft Graph Connection" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Check your credentials and network connectivity"
        return $allResults
    }
    
    # Test Graph permissions
    $graphResults = Test-MicrosoftGraphPermissions -RequiredScopes $requiredGraphScopes
    $allResults += $graphResults
    
    # Test Exchange Online connection
    try {
        Test-ExchangeOnlineConnection -TenantId $TenantId
        $allResults += Write-TestResult -TestName "Exchange Online Connection" -Success $true
    }
    catch {
        $allResults += Write-TestResult -TestName "Exchange Online Connection" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Check your Exchange Online access and licensing"
        return $allResults
    }
    
    # Test Exchange Online permissions
    $exchangeResults = Test-ExchangeOnlinePermissions
    $allResults += $exchangeResults
    
    return $allResults
}

function Test-NonHumanAccessPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId
    )
    
    Write-Host "`n🔍 Testing permissions for Exchange Online Non-Human Access Audit Script..." -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    $allResults = @()
    $requiredGraphScopes = @("Directory.Read.All", "Application.Read.All", "AppRoleAssignment.Read.All")
    
    # Test Microsoft Graph connection
    try {
        Test-GraphConnection -TenantId $TenantId
        $allResults += Write-TestResult -TestName "Microsoft Graph Connection" -Success $true
    }
    catch {
        $allResults += Write-TestResult -TestName "Microsoft Graph Connection" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Check your credentials and network connectivity"
        return $allResults
    }
    
    # Test Graph permissions
    $graphResults = Test-MicrosoftGraphPermissions -RequiredScopes $requiredGraphScopes
    $allResults += $graphResults
    
    # Test Exchange Online connection
    try {
        Test-ExchangeOnlineConnection -TenantId $TenantId
        $allResults += Write-TestResult -TestName "Exchange Online Connection" -Success $true
    }
    catch {
        $allResults += Write-TestResult -TestName "Exchange Online Connection" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Check your Exchange Online access and licensing"
        return $allResults
    }
    
    # Test Exchange Online permissions
    $exchangeResults = Test-ExchangeOnlinePermissions
    $allResults += $exchangeResults
    
    # Additional tests for non-human access
    try {
        Get-MgServicePrincipal -Top 1 -ErrorAction Stop | Out-Null
        $allResults += Write-TestResult -TestName "Microsoft Graph - Service Principal Access" -Success $true
    }
    catch {
        $allResults += Write-TestResult -TestName "Microsoft Graph - Service Principal Access" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Ensure you have permissions to read service principals"
    }
    
    try {
        Get-MgOauth2PermissionGrant -Top 1 -ErrorAction Stop | Out-Null
        $allResults += Write-TestResult -TestName "Microsoft Graph - OAuth2 Permission Grants" -Success $true
    }
    catch {
        $allResults += Write-TestResult -TestName "Microsoft Graph - OAuth2 Permission Grants" -Success $false -ErrorMessage $_.Exception.Message -Recommendation "Ensure you have permissions to read OAuth2 permission grants"
    }
    
    return $allResults
}
#endregion

#region Main Execution
try {
    Write-Host "Exchange Online Audit Scripts - Permission Testing Tool" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host "Testing permissions for Exchange Online role assignment audit scripts..." -ForegroundColor White
    
    # Determine what to test
    if ($TestAll) {
        $TestHumanAccess = $true
        $TestNonHumanAccess = $true
    }
    
    if (-not $TestHumanAccess -and -not $TestNonHumanAccess) {
        Write-Host "No test specified. Use -TestAll, -TestHumanAccess, or -TestNonHumanAccess" -ForegroundColor Yellow
        return
    }
    
    # Initialize modules
    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement', 'Microsoft.Graph.Applications', 'ExchangeOnlineManagement')
    
    foreach ($module in $requiredModules) {
        try {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Host "Installing module: $module" -ForegroundColor Yellow
                Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction Stop
            }
            
            if (-not (Get-Module -Name $module)) {
                Import-Module -Name $module -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Host "Failed to initialize module $($module): $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
    
    $allTestResults = @()
    
    # Test Human Access permissions
    if ($TestHumanAccess) {
        $humanResults = Test-HumanAccessPermissions -TenantId $TenantId
        $allTestResults += $humanResults
    }
    
    # Test Non-Human Access permissions
    if ($TestNonHumanAccess) {
        $nonHumanResults = Test-NonHumanAccessPermissions -TenantId $TenantId
        $allTestResults += $nonHumanResults
    }
    
    # Summary
    $totalTests = $allTestResults.Count
    $passedTests = ($allTestResults | Where-Object { $_ -eq $true }).Count
    $failedTests = $totalTests - $passedTests
    
    Write-Host "`n📊 Test Summary:" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "Total Tests: $totalTests" -ForegroundColor White
    Write-Host "Passed: $passedTests" -ForegroundColor Green
    Write-Host "Failed: $failedTests" -ForegroundColor Red
    
    if ($failedTests -eq 0) {
        Write-Host "`n🎉 All tests passed! You have the necessary permissions to run the Exchange Online audit scripts." -ForegroundColor Green
    } else {
        Write-Host "`n⚠️ Some tests failed. Please review the recommendations above and ensure you have the proper permissions." -ForegroundColor Yellow
        Write-Host "Refer to EXCHANGE_ONLINE_PERMISSIONS_GUIDE.md for detailed permission requirements." -ForegroundColor Cyan
    }
}
catch {
    Write-Host "Test execution failed: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
#endregion