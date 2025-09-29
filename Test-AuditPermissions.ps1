#Requires -Version 5.1
<#
.SYNOPSIS
    Test and validate permissions required for Azure role assignment audit scripts
    
.DESCRIPTION
    This script tests the minimum required API permissions and user roles needed to run
    the Azure role assignment audit scripts. It provides detailed feedback on missing
    permissions and suggests remediation steps.
    
.PARAMETER TenantId
    The Azure Tenant ID to test permissions against. If not specified, uses current context.
    
.PARAMETER TestEntraIDPermissions
    Switch to test permissions required for Entra ID role assignments script
    
.PARAMETER TestAzureResourcePermissions  
    Switch to test permissions required for Azure Resource RBAC script
    
.PARAMETER TestAll
    Switch to test all permissions for both scripts
    
.EXAMPLE
    .\Test-AuditPermissions.ps1 -TestAll
    
.EXAMPLE
    .\Test-AuditPermissions.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -TestEntraIDPermissions
    
.NOTES
    Author: Azure Audit Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestEntraIDPermissions,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestAzureResourcePermissions,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestAll
)

# Set defaults if no specific test is requested
if (-not $TestEntraIDPermissions -and -not $TestAzureResourcePermissions -and -not $TestAll) {
    $TestAll = $true
}

if ($TestAll) {
    $TestEntraIDPermissions = $true
    $TestAzureResourcePermissions = $true
}

# Test results tracking
$testResults = @()

function Write-TestResult {
    param(
        [string]$Test,
        [string]$Component,
        [bool]$Passed,
        [string]$Message,
        [string]$Remediation = ""
    )
    
    $color = if ($Passed) { 'Green' } else { 'Red' }
    $status = if ($Passed) { 'PASS' } else { 'FAIL' }
    
    Write-Host "[$status] $Component - $Test" -ForegroundColor $color
    if ($Message) {
        Write-Host "       $Message" -ForegroundColor Gray
    }
    if (-not $Passed -and $Remediation) {
        Write-Host "       Remediation: $Remediation" -ForegroundColor Yellow
    }
    
    $script:testResults += [PSCustomObject]@{
        Component = $Component
        Test = $Test
        Status = $status
        Passed = $Passed
        Message = $Message
        Remediation = $Remediation
    }
}

function Test-GraphConnection {
    param([string]$TenantId)
    
    try {
        if ($TenantId) {
            Connect-MgGraph -TenantId $TenantId -Scopes "Directory.Read.All" -NoWelcome -ErrorAction Stop
        } else {
            Connect-MgGraph -Scopes "Directory.Read.All" -NoWelcome -ErrorAction Stop
        }
        
        $context = Get-MgContext
        Write-TestResult -Test "Graph Connection" -Component "Prerequisites" -Passed $true -Message "Connected to tenant: $($context.TenantId)"
        return $true
    }
    catch {
        Write-TestResult -Test "Graph Connection" -Component "Prerequisites" -Passed $false -Message $_.Exception.Message -Remediation "Run Connect-MgGraph with appropriate scopes"
        return $false
    }
}

function Test-AzConnection {
    param([string]$TenantId)
    
    try {
        if ($TenantId) {
            Connect-AzAccount -TenantId $TenantId -ErrorAction Stop | Out-Null
        } else {
            $context = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $context) {
                Connect-AzAccount -ErrorAction Stop | Out-Null
            }
        }
        
        $context = Get-AzContext
        Write-TestResult -Test "Azure Connection" -Component "Prerequisites" -Passed $true -Message "Connected to tenant: $($context.Tenant.Id)"
        return $true
    }
    catch {
        Write-TestResult -Test "Azure Connection" -Component "Prerequisites" -Passed $false -Message $_.Exception.Message -Remediation "Run Connect-AzAccount with appropriate permissions"
        return $false
    }
}

function Test-EntraIDRolePermissions {
    Write-Host "`n=== Testing Entra ID Role Assignment Permissions ===" -ForegroundColor Cyan
    
    # Test Graph context and scopes
    $context = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-TestResult -Test "Graph Context" -Component "Entra ID" -Passed $false -Message "Not connected to Microsoft Graph" -Remediation "Connect to Microsoft Graph first"
        return
    }
    
    $requiredScopes = @('Directory.Read.All', 'RoleManagement.Read.All', 'PrivilegedAccess.Read.AzureAD')
    
    foreach ($scope in $requiredScopes) {
        $hasScope = $scope -in $context.Scopes
        $remediation = if (-not $hasScope) { "Request $scope permission and admin consent" } else { "" }
        Write-TestResult -Test "Scope: $scope" -Component "Entra ID" -Passed $hasScope -Message $(if ($hasScope) { "Available" } else { "Missing" }) -Remediation $remediation
    }
    
    # Test actual API calls
    try {
        $roles = Get-MgDirectoryRole -ErrorAction Stop
        Write-TestResult -Test "Directory Role Access" -Component "Entra ID" -Passed $true -Message "Can read directory roles"
    }
    catch {
        Write-TestResult -Test "Directory Role Access" -Component "Entra ID" -Passed $false -Message $_.Exception.Message -Remediation "Ensure RoleManagement.Read.All permission"
    }
    
    try {
        $users = Get-MgUser -Top 1 -ErrorAction Stop
        Write-TestResult -Test "User Directory Access" -Component "Entra ID" -Passed $true -Message "Can read user directory"
    }
    catch {
        Write-TestResult -Test "User Directory Access" -Component "Entra ID" -Passed $false -Message $_.Exception.Message -Remediation "Ensure Directory.Read.All permission"
    }
    
    try {
        $pimResources = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Top 1 -ErrorAction Stop
        Write-TestResult -Test "PIM Access (Entra ID)" -Component "Entra ID" -Passed $true -Message "Can read PIM resources"
    }
    catch {
        Write-TestResult -Test "PIM Access (Entra ID)" -Component "Entra ID" -Passed $false -Message $_.Exception.Message -Remediation "Ensure PrivilegedAccess.Read.AzureAD permission and sufficient role"
    }
}

function Test-AzureResourcePermissions {
    Write-Host "`n=== Testing Azure Resource RBAC Permissions ===" -ForegroundColor Cyan
    
    # Test Azure context
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Write-TestResult -Test "Azure Context" -Component "Azure RBAC" -Passed $false -Message "Not connected to Azure" -Remediation "Connect to Azure first"
        return
    }
    
    Write-TestResult -Test "Azure Context" -Component "Azure RBAC" -Passed $true -Message "Connected to subscription: $($context.Subscription.Name)"
    
    # Test subscription access
    try {
        $subscriptions = Get-AzSubscription -ErrorAction Stop
        Write-TestResult -Test "Subscription Access" -Component "Azure RBAC" -Passed $true -Message "Can read $($subscriptions.Count) subscription(s)"
    }
    catch {
        Write-TestResult -Test "Subscription Access" -Component "Azure RBAC" -Passed $false -Message $_.Exception.Message -Remediation "Ensure Reader role on subscriptions"
    }
    
    # Test management group access
    try {
        $mgGroups = Get-AzManagementGroup -ErrorAction Stop
        Write-TestResult -Test "Management Group Access" -Component "Azure RBAC" -Passed $true -Message "Can read $($mgGroups.Count) management group(s)"
    }
    catch {
        Write-TestResult -Test "Management Group Access" -Component "Azure RBAC" -Passed $false -Message $_.Exception.Message -Remediation "Ensure Reader role at management group level"
    }
    
    # Test role assignment access
    try {
        $roleAssignments = Get-AzRoleAssignment -Scope "/" -Top 1 -ErrorAction Stop
        Write-TestResult -Test "Role Assignment Access" -Component "Azure RBAC" -Passed $true -Message "Can read role assignments"
    }
    catch {
        Write-TestResult -Test "Role Assignment Access" -Component "Azure RBAC" -Passed $false -Message $_.Exception.Message -Remediation "Ensure Reader role with sufficient scope"
    }
    
    # Test Azure PIM access
    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($graphContext -and 'PrivilegedAccess.Read.AzureResources' -in $graphContext.Scopes) {
        try {
            $azurePimResources = Get-MgIdentityGovernancePrivilegedAccessResource -PrivilegedAccessId 'azureResources' -Top 1 -ErrorAction Stop
            Write-TestResult -Test "PIM Access (Azure Resources)" -Component "Azure RBAC" -Passed $true -Message "Can read Azure PIM resources"
        }
        catch {
            Write-TestResult -Test "PIM Access (Azure Resources)" -Component "Azure RBAC" -Passed $false -Message $_.Exception.Message -Remediation "Ensure PrivilegedAccess.Read.AzureResources permission and sufficient role"
        }
    } else {
        Write-TestResult -Test "PIM Access (Azure Resources)" -Component "Azure RBAC" -Passed $false -Message "Missing PrivilegedAccess.Read.AzureResources scope" -Remediation "Connect to Graph with PrivilegedAccess.Read.AzureResources scope"
    }
}

function Show-Summary {
    Write-Host "`n=== PERMISSION TEST SUMMARY ===" -ForegroundColor Magenta
    
    $groupedResults = $testResults | Group-Object Component
    
    foreach ($group in $groupedResults) {
        $componentResults = $group.Group
        $passed = ($componentResults | Where-Object { $_.Passed }).Count
        $total = $componentResults.Count
        $percentage = [math]::Round(($passed / $total) * 100, 1)
        
        $color = if ($percentage -eq 100) { 'Green' } elseif ($percentage -ge 80) { 'Yellow' } else { 'Red' }
        Write-Host "$($group.Name): $passed/$total tests passed ($percentage%)" -ForegroundColor $color
    }
    
    $overallPassed = ($testResults | Where-Object { $_.Passed }).Count
    $overallTotal = $testResults.Count
    $overallPercentage = [math]::Round(($overallPassed / $overallTotal) * 100, 1)
    
    Write-Host "`nOverall: $overallPassed/$overallTotal tests passed ($overallPercentage%)" -ForegroundColor $(if ($overallPercentage -eq 100) { 'Green' } else { 'Yellow' })
    
    # Show failed tests with remediation
    $failedTests = $testResults | Where-Object { -not $_.Passed }
    if ($failedTests.Count -gt 0) {
        Write-Host "`n=== FAILED TESTS REQUIRING ATTENTION ===" -ForegroundColor Red
        foreach ($test in $failedTests) {
            Write-Host "❌ $($test.Component) - $($test.Test)" -ForegroundColor Red
            if ($test.Remediation) {
                Write-Host "   💡 $($test.Remediation)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "`n✅ All permission tests passed! You can run the audit scripts." -ForegroundColor Green
    }
}

# Main execution
Write-Host "Azure Role Assignment Audit Scripts - Permission Validator" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green

# Test prerequisite connections
$graphConnected = Test-GraphConnection -TenantId $TenantId
$azureConnected = if ($TestAzureResourcePermissions) { Test-AzConnection -TenantId $TenantId } else { $true }

# Run specific permission tests
if ($TestEntraIDPermissions -and $graphConnected) {
    Test-EntraIDRolePermissions
}

if ($TestAzureResourcePermissions -and $azureConnected -and $graphConnected) {
    Test-AzureResourcePermissions
}

# Show summary
Show-Summary

Write-Host "`nFor detailed permission requirements, see: PERMISSIONS_GUIDE.md" -ForegroundColor Cyan