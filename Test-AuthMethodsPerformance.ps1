#Requires -Version 5.1
<#
.SYNOPSIS
    Tests authentication methods API performance to diagnose slowdown issues
    
.DESCRIPTION
    This script tests the Microsoft Graph authentication methods APIs to:
    - Measure response times for different authentication method types
    - Identify potential bottlenecks in the audit process
    - Provide recommendations for optimizing the audit script
    
.PARAMETER TenantId
    Azure Tenant ID to test against
    
.PARAMETER SampleSize
    Number of users to test (default: 5, max: 25)
    
.PARAMETER TestTimeout
    Timeout in seconds for each API call (default: 30)
    
.EXAMPLE
    .\Test-AuthMethodsPerformance.ps1 -TenantId "1f05524b-c860-46e3-a2e8-4072506b3e4a" -SampleSize 5
    
.NOTES
    Author: Azure Security Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
    
    This script helps diagnose performance issues with the Audit-AzureAuthMethods.ps1 script
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$SampleSize = 5,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 120)]
    [int]$TestTimeout = 30
)

# Required modules for authentication methods testing
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users',
    'Microsoft.Graph.Identity.SignIns'
)

# Authentication method cmdlets to test
$AuthMethodCmdlets = @{
    'Phone' = 'Get-MgUserAuthenticationPhoneMethod'
    'Email' = 'Get-MgUserAuthenticationEmailMethod'
    'Fido2' = 'Get-MgUserAuthenticationFido2Method'
    'Authenticator' = 'Get-MgUserAuthenticationMicrosoftAuthenticatorMethod'
    'HelloBusiness' = 'Get-MgUserAuthenticationWindowsHelloForBusinessMethod'
    'TAP' = 'Get-MgUserAuthenticationTemporaryAccessPassMethod'
    'SoftwareOath' = 'Get-MgUserAuthenticationSoftwareOathMethod'
}

# Logging function
function Write-TestLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'Info' { 'White' }
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Test-ModuleAvailability {
    Write-TestLog "Testing module availability..." -Level 'Info'
    
    foreach ($module in $RequiredModules) {
        try {
            Import-Module -Name $module -Force -ErrorAction Stop
            Write-TestLog "✅ Module imported: $module" -Level 'Success'
        }
        catch {
            Write-TestLog "❌ Failed to import module: $module" -Level 'Error'
            throw "Required module $module is not available"
        }
    }
}

function Test-GraphConnection {
    Write-TestLog "Testing Graph connection..." -Level 'Info'
    
    try {
        $currentContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($currentContext -and $currentContext.TenantId -eq $TenantId) {
            Write-TestLog "✅ Already connected to target tenant: $TenantId" -Level 'Success'
            return $true
        }
        
        Write-TestLog "Connecting to Microsoft Graph..." -Level 'Info'
        Connect-MgGraph -TenantId $TenantId -Scopes @('User.Read.All', 'UserAuthenticationMethod.Read.All') -ErrorAction Stop
        $newContext = Get-MgContext
        Write-TestLog "✅ Connected to tenant: $($newContext.TenantId)" -Level 'Success'
        return $true
    }
    catch {
        Write-TestLog "❌ Graph connection failed: $($_.Exception.Message)" -Level 'Error'
        return $false
    }
}

function Get-SampleUsers {
    Write-TestLog "Retrieving sample users..." -Level 'Info'
    
    try {
        $users = Get-MgUser -Filter "userType eq 'Member'" -Top $SampleSize -Select "Id,UserPrincipalName,DisplayName" -ErrorAction Stop
        Write-TestLog "✅ Retrieved $($users.Count) sample users" -Level 'Success'
        return $users
    }
    catch {
        Write-TestLog "❌ Failed to retrieve users: $($_.Exception.Message)" -Level 'Error'
        throw
    }
}

function Test-AuthMethodAPI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId,
        
        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,
        
        [Parameter(Mandatory = $true)]
        [string]$MethodName,
        
        [Parameter(Mandatory = $true)]
        [string]$Cmdlet
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        # Use timeout wrapper for API calls
        $scriptBlock = {
            param($Cmdlet, $UserId)
            & $Cmdlet -UserId $UserId -ErrorAction SilentlyContinue
        }
        
        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $Cmdlet, $UserId
        $methods = $job | Wait-Job -Timeout $TestTimeout | Receive-Job
        $job | Remove-Job -Force
        
        $stopwatch.Stop()
        $responseTime = $stopwatch.ElapsedMilliseconds
        
        if ($null -eq $methods) {
            $methods = @()
        }
        
        return @{
            Success = $true
            MethodCount = $methods.Count
            ResponseTime = $responseTime
            ErrorMessage = $null
        }
    }
    catch {
        $stopwatch.Stop()
        return @{
            Success = $false
            MethodCount = 0
            ResponseTime = $stopwatch.ElapsedMilliseconds
            ErrorMessage = $_.Exception.Message
        }
    }
}

function Test-UserAuthMethods {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User
    )
    
    Write-TestLog "Testing user: $($User.UserPrincipalName)" -Level 'Info'
    $userResults = @{}
    $totalStartTime = Get-Date
    
    foreach ($methodName in $AuthMethodCmdlets.Keys) {
        $cmdlet = $AuthMethodCmdlets[$methodName]
        
        Write-TestLog "  Testing $methodName methods..." -Level 'Info'
        $result = Test-AuthMethodAPI -UserId $User.Id -UserPrincipalName $User.UserPrincipalName -MethodName $methodName -Cmdlet $cmdlet
        
        if ($result.Success) {
            Write-TestLog "    ✅ $methodName`: $($result.MethodCount) methods ($($result.ResponseTime)ms)" -Level 'Success'
        } else {
            Write-TestLog "    ❌ $methodName`: FAILED ($($result.ResponseTime)ms) - $($result.ErrorMessage)" -Level 'Error'
        }
        
        $userResults[$methodName] = $result
        
        # Small delay between method types
        Start-Sleep -Milliseconds 200
    }
    
    $totalTime = ((Get-Date) - $totalStartTime).TotalMilliseconds
    $userResults['TotalTime'] = $totalTime
    $userResults['UserPrincipalName'] = $User.UserPrincipalName
    
    Write-TestLog "  Total time for user: $([math]::Round($totalTime / 1000, 1))s" -Level 'Info'
    
    return $userResults
}

# Main execution
try {
    Write-TestLog "🧪 Starting Authentication Methods Performance Test" -Level 'Info'
    Write-TestLog "Tenant: $TenantId" -Level 'Info'
    Write-TestLog "Sample Size: $SampleSize users" -Level 'Info'
    Write-TestLog "Timeout: $TestTimeout seconds per API call" -Level 'Info'
    Write-TestLog ("=" * 60) -Level 'Info'
    
    # Test module availability
    Test-ModuleAvailability
    
    # Test Graph connection
    if (-not (Test-GraphConnection)) {
        throw "Cannot connect to Microsoft Graph"
    }
    
    # Get sample users
    $sampleUsers = Get-SampleUsers
    
    if ($sampleUsers.Count -eq 0) {
        throw "No users found for testing"
    }
    
    # Test each user
    $allResults = @()
    $testStartTime = Get-Date
    
    for ($i = 0; $i -lt $sampleUsers.Count; $i++) {
        $user = $sampleUsers[$i]
        Write-TestLog "`n[$($i + 1)/$($sampleUsers.Count)] Testing user: $($user.DisplayName)" -Level 'Info'
        
        try {
            $userResult = Test-UserAuthMethods -User $user
            $allResults += $userResult
        }
        catch {
            Write-TestLog "  ❌ Failed to test user: $($_.Exception.Message)" -Level 'Error'
        }
    }
    
    $totalTestTime = (Get-Date) - $testStartTime
    
    # Generate summary
    Write-TestLog "`n📊 PERFORMANCE TEST SUMMARY" -Level 'Info'
    Write-TestLog ("=" * 60) -Level 'Info'
    
    if ($allResults.Count -gt 0) {
        $avgTimePerUser = ($allResults | ForEach-Object { $_.TotalTime } | Measure-Object -Average).Average
        $maxTimePerUser = ($allResults | ForEach-Object { $_.TotalTime } | Measure-Object -Maximum).Maximum
        
        Write-TestLog "Total Test Time: $([math]::Round($totalTestTime.TotalMinutes, 1)) minutes" -Level 'Info'
        Write-TestLog "Average Time Per User: $([math]::Round($avgTimePerUser / 1000, 1)) seconds" -Level 'Info'
        Write-TestLog "Max Time Per User: $([math]::Round($maxTimePerUser / 1000, 1)) seconds" -Level 'Info'
        
        # Method-specific analysis
        Write-TestLog "`n📈 METHOD PERFORMANCE ANALYSIS:" -Level 'Info'
        foreach ($methodName in $AuthMethodCmdlets.Keys) {
            $methodResults = $allResults | ForEach-Object { $_[$methodName] } | Where-Object { $null -ne $_ }
            if ($methodResults.Count -gt 0) {
                $successRate = ($methodResults | Where-Object { $_.Success }).Count / $methodResults.Count * 100
                $avgResponseTime = ($methodResults | ForEach-Object { $_.ResponseTime } | Measure-Object -Average).Average
                
                $status = if ($successRate -eq 100) { "✅" } else { "⚠️" }
                Write-TestLog "  $status $methodName`: $([math]::Round($successRate, 1))% success, avg $([math]::Round($avgResponseTime))ms" -Level 'Info'
            }
        }
        
        # Recommendations
        Write-TestLog "`n💡 RECOMMENDATIONS:" -Level 'Info'
        
        if ($avgTimePerUser -gt 10000) {  # More than 10 seconds per user
            Write-TestLog "  ⚠️  High response times detected. Consider:" -Level 'Warning'
            Write-TestLog "     - Reducing batch size (use -BatchSize 10-15)" -Level 'Warning'
            Write-TestLog "     - Adding delays between API calls" -Level 'Warning'
            Write-TestLog "     - Running during off-peak hours" -Level 'Warning'
        }
        
        $projectedTime = ($avgTimePerUser / 1000) * 697 / 60  # For your 697 users
        Write-TestLog "`n🕐 ESTIMATED TIME FOR 697 USERS:" -Level 'Info'
        Write-TestLog "   Projected completion time: $([math]::Round($projectedTime, 1)) minutes" -Level 'Info'
        
        if ($projectedTime -gt 60) {
            Write-TestLog "   ⚠️  This is quite long. Recommended optimizations:" -Level 'Warning'
            Write-TestLog "     - Use smaller batch sizes (-BatchSize 10)" -Level 'Warning'
            Write-TestLog "     - Run during low-activity hours" -Level 'Warning'
            Write-TestLog "     - Consider filtering to specific user groups first" -Level 'Warning'
        } else {
            Write-TestLog "   ✅ Projected time looks reasonable!" -Level 'Success'
        }
    } else {
        Write-TestLog "No results to analyze - all users failed" -Level 'Error'
    }
    
    Write-TestLog "`n✅ Performance test completed successfully!" -Level 'Success'
    
} catch {
    Write-TestLog "`n❌ Performance test failed: $($_.Exception.Message)" -Level 'Error'
    Write-TestLog "Stack trace: $($_.ScriptStackTrace)" -Level 'Error'
    exit 1
}