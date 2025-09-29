#Requires -Version 5.1
<#
.SYNOPSIS
    Test script to validate PowerShell 5.1 compatibility for Azure audit scripts
    
.DESCRIPTION
    This script tests the compatibility of the Azure role assignment audit scripts
    with Windows PowerShell 5.1. It performs syntax validation and basic functionality
    testing in dry-run mode.
    
.NOTES
    Author: Azure Audit Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
#>

[CmdletBinding()]
param()

Write-Host "Testing PowerShell 5.1 Compatibility for Azure Audit Scripts" -ForegroundColor Green
Write-Host "=============================================================" -ForegroundColor Green

# Display PowerShell version
Write-Host "`nPowerShell Version Information:" -ForegroundColor Cyan
$PSVersionTable | Format-Table -AutoSize

# Test script variables
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$testTenantId = "12345678-1234-1234-1234-123456789012"

# Test scripts to validate
$scriptsToTest = @(
    @{
        Name = "Entra ID Role Assignments"
        Path = Join-Path $scriptPath "Audit-EntraIDRoleAssignments.ps1"
        Command = "& `"{0}`" -TenantIds @(`"{1}`") -DryRun" -f (Join-Path $scriptPath "Audit-EntraIDRoleAssignments.ps1"), $testTenantId
    },
    @{
        Name = "Azure Resource RBAC"
        Path = Join-Path $scriptPath "Audit-AzureResourceRBAC.ps1"
        Command = "& `"{0}`" -TenantIds @(`"{1}`") -DryRun" -f (Join-Path $scriptPath "Audit-AzureResourceRBAC.ps1"), $testTenantId
    },
    @{
        Name = "Azure Auth Methods"
        Path = Join-Path $scriptPath "Audit-AzureAuthMethods.ps1"
        Command = "& `"{0}`" -TenantIds @(`"{1}`") -DryRun" -f (Join-Path $scriptPath "Audit-AzureAuthMethods.ps1"), $testTenantId
    },
    @{
        Name = "Permission Test"
        Path = Join-Path $scriptPath "Test-AuditPermissions.ps1"
        Command = "& `"{0}`" -TestAll" -f (Join-Path $scriptPath "Test-AuditPermissions.ps1")
    }
)

$testResults = @()

foreach ($script in $scriptsToTest) {
    Write-Host "`nTesting: $($script.Name)" -ForegroundColor Yellow
    Write-Host "Script: $($script.Path)" -ForegroundColor Gray
    
    # Test if file exists
    if (-not (Test-Path $script.Path)) {
        Write-Host "❌ FAIL: Script file not found" -ForegroundColor Red
        $testResults += [PSCustomObject]@{
            Script = $script.Name
            Test = "File Exists"
            Result = "FAIL"
            Error = "File not found"
        }
        continue
    }
    
    # Test syntax validation
    try {
        $syntaxErrors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script.Path, [ref]$tokens, [ref]$syntaxErrors)
        
        if ($syntaxErrors.Count -gt 0) {
            Write-Host "❌ FAIL: Syntax errors found" -ForegroundColor Red
            foreach ($error in $syntaxErrors) {
                Write-Host "   Line $($error.Extent.StartLineNumber): $($error.Message)" -ForegroundColor Red
            }
            $testResults += [PSCustomObject]@{
                Script = $script.Name
                Test = "Syntax Validation"
                Result = "FAIL"
                Error = "Syntax errors: $($syntaxErrors.Count)"
            }
            continue
        }
        else {
            Write-Host "✅ PASS: Syntax validation" -ForegroundColor Green
            $testResults += [PSCustomObject]@{
                Script = $script.Name
                Test = "Syntax Validation"
                Result = "PASS"
                Error = $null
            }
        }
    }
    catch {
        Write-Host "❌ FAIL: Syntax validation error - $($_.Exception.Message)" -ForegroundColor Red
        $testResults += [PSCustomObject]@{
            Script = $script.Name
            Test = "Syntax Validation"
            Result = "FAIL"
            Error = $_.Exception.Message
        }
        continue
    }
    
    # Test execution (dry-run mode only for safety)
    if ($script.Name -ne "Permission Test") {
        try {
            Write-Host "⏳ Testing execution in dry-run mode..." -ForegroundColor Cyan
            
            # Use PowerShell 5.1 to execute
            $ps51Path = "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\powershell.exe"
            $result = & $ps51Path -ExecutionPolicy Bypass -Command $script.Command
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ PASS: Script execution" -ForegroundColor Green
                $testResults += [PSCustomObject]@{
                    Script = $script.Name
                    Test = "Execution Test"
                    Result = "PASS"
                    Error = $null
                }
            }
            else {
                Write-Host "❌ FAIL: Script execution failed with exit code $LASTEXITCODE" -ForegroundColor Red
                $testResults += [PSCustomObject]@{
                    Script = $script.Name
                    Test = "Execution Test"
                    Result = "FAIL"
                    Error = "Exit code: $LASTEXITCODE"
                }
            }
        }
        catch {
            Write-Host "❌ FAIL: Script execution error - $($_.Exception.Message)" -ForegroundColor Red
            $testResults += [PSCustomObject]@{
                Script = $script.Name
                Test = "Execution Test"
                Result = "FAIL"
                Error = $_.Exception.Message
            }
        }
    }
}

# Summary results
Write-Host "`n" + "="*60 -ForegroundColor Green
Write-Host "COMPATIBILITY TEST SUMMARY" -ForegroundColor Green
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
    Write-Host "`n🎉 ALL TESTS PASSED! Scripts are compatible with PowerShell 5.1" -ForegroundColor Green
    Write-Host "✅ Ready for production use in PowerShell 5.1 environments" -ForegroundColor Green
}
else {
    Write-Host "`n⚠️  COMPATIBILITY ISSUES FOUND" -ForegroundColor Red
    Write-Host "❌ Scripts require fixes before use in PowerShell 5.1 environments" -ForegroundColor Red
    
    $failedTests = $testResults | Where-Object { $_.Result -eq "FAIL" }
    Write-Host "`nFailed Tests:" -ForegroundColor Red
    foreach ($test in $failedTests) {
        Write-Host "  • $($test.Script) - $($test.Test): $($test.Error)" -ForegroundColor Red
    }
}

Write-Host "`nCompatibility test completed!" -ForegroundColor Cyan