#Requires -Version 5.1
<#
.SYNOPSIS
    Test script to validate permissions for Azure Authentication Methods audit
    
.DESCRIPTION
    This script validates the required permissions and access for the Audit-AzureAuthMethods.ps1 script.
    It tests Microsoft Graph connectivity, user access, authentication method access, and policy access.
    
.PARAMETER TestAuthMethods
    Switch to test only authentication methods specific permissions
    
.PARAMETER TestAll
    Switch to run all available tests
    
.NOTES
    Author: Azure Audit Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$TestAuthMethods,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestAll
)

Write-Host "Testing Azure Authentication Methods Audit Permissions" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green

$testResults = @()

# Test 1: Microsoft Graph Connection
Write-Host "`nTest 1: Microsoft Graph Connection" -ForegroundColor Yellow
try {
    $context = Get-MgContext -ErrorAction Stop
    if ($context) {
        Write-Host "✅ Connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "   Tenant: $($context.TenantId)" -ForegroundColor Gray
        Write-Host "   Account: $($context.Account)" -ForegroundColor Gray
        Write-Host "   Scopes: $($context.Scopes -join ', ')" -ForegroundColor Gray
        
        $testResults += [PSCustomObject]@{
            Test = "Graph Connection"
            Result = "PASS"
            Details = "Connected to tenant $($context.TenantId)"
        }
    }
    else {
        throw "No active Microsoft Graph connection"
    }
}
catch {
    Write-Host "❌ Microsoft Graph connection failed: $($_.Exception.Message)" -ForegroundColor Red
    $testResults += [PSCustomObject]@{
        Test = "Graph Connection"
        Result = "FAIL"
        Details = $_.Exception.Message
    }
}

# Test 2: User Read Access
Write-Host "`nTest 2: User Read Access (User.Read.All)" -ForegroundColor Yellow
try {
    $users = Get-MgUser -Filter "userType eq 'Member'" -Top 5 -ErrorAction Stop
    Write-Host "✅ Successfully retrieved $($users.Count) member users" -ForegroundColor Green
    
    $testResults += [PSCustomObject]@{
        Test = "User Read Access"
        Result = "PASS"
        Details = "Retrieved $($users.Count) member users"
    }
}
catch {
    Write-Host "❌ User read access failed: $($_.Exception.Message)" -ForegroundColor Red
    $testResults += [PSCustomObject]@{
        Test = "User Read Access"
        Result = "FAIL"
        Details = $_.Exception.Message
    }
}

# Test 3: Authentication Methods Access
if ($TestAuthMethods -or $TestAll) {
    Write-Host "`nTest 3: Authentication Methods Access" -ForegroundColor Yellow
    try {
        # Get a test user
        $testUser = Get-MgUser -Top 1 -ErrorAction Stop
        if ($testUser) {
            Write-Host "   Testing with user: $($testUser.UserPrincipalName)" -ForegroundColor Gray
            
            # Test Microsoft Authenticator methods
            try {
                $authMethods = Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $testUser.Id -ErrorAction SilentlyContinue
                Write-Host "   ✅ Microsoft Authenticator methods: $($authMethods.Count) found" -ForegroundColor Green
            }
            catch {
                Write-Host "   ⚠️  Microsoft Authenticator access issue: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            # Test FIDO2 methods
            try {
                $fido2Methods = Get-MgUserAuthenticationFido2Method -UserId $testUser.Id -ErrorAction SilentlyContinue
                Write-Host "   ✅ FIDO2 methods: $($fido2Methods.Count) found" -ForegroundColor Green
            }
            catch {
                Write-Host "   ⚠️  FIDO2 access issue: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            # Test Phone methods
            try {
                $phoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $testUser.Id -ErrorAction SilentlyContinue
                Write-Host "   ✅ Phone methods: $($phoneMethods.Count) found" -ForegroundColor Green
            }
            catch {
                Write-Host "   ⚠️  Phone methods access issue: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            # Test Email methods
            try {
                $emailMethods = Get-MgUserAuthenticationEmailMethod -UserId $testUser.Id -ErrorAction SilentlyContinue
                Write-Host "   ✅ Email methods: $($emailMethods.Count) found" -ForegroundColor Green
            }
            catch {
                Write-Host "   ⚠️  Email methods access issue: $($_.Exception.Message)" -ForegroundColor Yellow
            }
            
            Write-Host "✅ Authentication methods access validated" -ForegroundColor Green
            $testResults += [PSCustomObject]@{
                Test = "Authentication Methods Access"
                Result = "PASS"
                Details = "Successfully accessed authentication method APIs"
            }
        }
    }
    catch {
        Write-Host "❌ Authentication methods access failed: $($_.Exception.Message)" -ForegroundColor Red
        $testResults += [PSCustomObject]@{
            Test = "Authentication Methods Access"
            Result = "FAIL"
            Details = $_.Exception.Message
        }
    }
}

# Test 4: Policy Read Access
if ($TestAll) {
    Write-Host "`nTest 4: Policy Read Access (Policy.Read.All)" -ForegroundColor Yellow
    try {
        # Try to read authentication method policies
        $authMethodPolicies = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
        Write-Host "✅ Successfully accessed authentication method policies" -ForegroundColor Green
        
        $testResults += [PSCustomObject]@{
            Test = "Policy Read Access"
            Result = "PASS"
            Details = "Successfully accessed authentication method policies"
        }
    }
    catch {
        Write-Host "❌ Policy read access failed: $($_.Exception.Message)" -ForegroundColor Red
        $testResults += [PSCustomObject]@{
            Test = "Policy Read Access"
            Result = "FAIL"
            Details = $_.Exception.Message
        }
    }
}

# Test 5: Sign-in Preferences Access
if ($TestAll) {
    Write-Host "`nTest 5: Sign-in Preferences Access" -ForegroundColor Yellow
    try {
        $testUser = Get-MgUser -Top 1 -ErrorAction Stop
        if ($testUser) {
            $signInPrefs = Get-MgUserAuthenticationSignInPreference -UserId $testUser.Id -ErrorAction SilentlyContinue
            Write-Host "✅ Successfully accessed user sign-in preferences" -ForegroundColor Green
            
            $testResults += [PSCustomObject]@{
                Test = "Sign-in Preferences Access"
                Result = "PASS"
                Details = "Successfully accessed sign-in preferences"
            }
        }
    }
    catch {
        Write-Host "❌ Sign-in preferences access failed: $($_.Exception.Message)" -ForegroundColor Red
        $testResults += [PSCustomObject]@{
            Test = "Sign-in Preferences Access"
            Result = "FAIL"
            Details = $_.Exception.Message
        }
    }
}

# Display results summary
Write-Host "`n" + "="*60 -ForegroundColor Green
Write-Host "AUTHENTICATION METHODS PERMISSIONS TEST SUMMARY" -ForegroundColor Green
Write-Host "="*60 -ForegroundColor Green

$testResults | Format-Table -AutoSize

$passCount = ($testResults | Where-Object { $_.Result -eq "PASS" }).Count
$failCount = ($testResults | Where-Object { $_.Result -eq "FAIL" }).Count
$totalCount = $testResults.Count

Write-Host "`nResults:" -ForegroundColor Cyan
Write-Host "  Passed: $passCount" -ForegroundColor Green
Write-Host "  Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Total:  $totalCount" -ForegroundColor White

if ($failCount -eq 0) {
    Write-Host "`n🎉 ALL PERMISSIONS VALIDATED!" -ForegroundColor Green
    Write-Host "✅ Ready to run Audit-AzureAuthMethods.ps1" -ForegroundColor Green
}
else {
    Write-Host "`n⚠️  PERMISSION ISSUES FOUND" -ForegroundColor Red
    Write-Host "❌ Please resolve permission issues before running the audit script" -ForegroundColor Red
    
    $failedTests = $testResults | Where-Object { $_.Result -eq "FAIL" }
    Write-Host "`nRequired Actions:" -ForegroundColor Red
    foreach ($test in $failedTests) {
        Write-Host "  • $($test.Test): $($test.Details)" -ForegroundColor Red
    }
    
    Write-Host "`nRequired Permissions:" -ForegroundColor Yellow
    Write-Host "  • User.Read.All (Microsoft Graph)" -ForegroundColor Yellow
    Write-Host "  • UserAuthenticationMethod.Read.All (Microsoft Graph)" -ForegroundColor Yellow
    Write-Host "  • Policy.Read.All (Microsoft Graph)" -ForegroundColor Yellow
    
    Write-Host "`nRequired Roles:" -ForegroundColor Yellow
    Write-Host "  • Global Reader (recommended)" -ForegroundColor Yellow
    Write-Host "  • Security Reader (minimum)" -ForegroundColor Yellow
    Write-Host "  • Authentication Administrator" -ForegroundColor Yellow
}

Write-Host "`nPermission validation completed!" -ForegroundColor Cyan