#Requires -Version 5.1
<#
.SYNOPSIS
    Analyzes Azure authentication methods audit data to plan passwordless MFA migration strategy
    
.DESCRIPTION
    This script analyzes the output from Audit-AzureAuthMethods.ps1 to:
    - Categorize users by current authentication method readiness
    - Identify users ready for passwordless migration
    - Recommend migration waves and pilot groups
    - Generate detailed migration planning reports with risk assessment
    
.PARAMETER AuthMethodsReportPath
    Path to the AzureAuthMethods CSV report from the audit
    
.PARAMETER ComplianceReportPath
    Path to the NISTCompliance CSV report from the audit
    
.PARAMETER ExportPath
    Directory to save migration planning reports
    
.PARAMETER PilotGroupSize
    Number of users for the pilot group (default: 25)
    
.EXAMPLE
    .\Analyze-PasswordlessMigration.ps1 -AuthMethodsReportPath ".\AzureAuthMethods_tenant_20250904.csv" -ComplianceReportPath ".\NISTCompliance_tenant_20250904.csv"
    
.NOTES
    Author: Azure Security Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
    
    This script helps plan the migration from SMS/Email to Passwordless MFA with Authenticator app
    Based on data from Audit-AzureAuthMethods.ps1 script
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the AzureAuthMethods CSV report")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$AuthMethodsReportPath,
    
    [Parameter(Mandatory = $true, HelpMessage = "Path to the NISTCompliance CSV report")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ComplianceReportPath,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 100)]
    [int]$PilotGroupSize = 25
)

# Import data from existing audit
Write-Host "📊 Loading authentication methods audit data..." -ForegroundColor Green
try {
    $authMethods = Import-Csv -Path $AuthMethodsReportPath
    $complianceData = Import-Csv -Path $ComplianceReportPath
    
    Write-Host "✅ Loaded $($authMethods.Count) authentication method records for $($complianceData.Count) users" -ForegroundColor White
}
catch {
    Write-Error "Failed to load audit data: $($_.Exception.Message)"
    exit 1
}

# User categorization for migration planning
$userCategories = @{
    ReadyForPasswordless = @()      # Users with Authenticator app already
    NeedsAuthenticator = @()        # Users without Authenticator app
    HighRisk = @()                  # Users with only SMS/Email
    AlreadyPasswordless = @()       # Users with FIDO2/WHFB only
    PilotCandidates = @()          # Ideal pilot group
    BlockedUsers = @()             # Users that cannot be migrated yet
}

# Risk assessment categories
$riskLevels = @{
    Critical = @()    # Only SMS/Email
    High = @()        # SMS/Email + weak methods
    Medium = @()      # Mixed strong/weak methods
    Low = @()         # Already has strong methods
}

Write-Host "🔍 Analyzing user authentication patterns..." -ForegroundColor Green

# Analyze each user
foreach ($user in $complianceData) {
    $userMethods = $authMethods | Where-Object { $_.UserPrincipalName -eq $user.UserPrincipalName }
    
    $hasAuthenticator = ($userMethods | Where-Object { $_.MethodType -eq 'Microsoft Authenticator' }).Count -gt 0
    $hasFIDO2 = ($userMethods | Where-Object { $_.MethodType -eq 'FIDO2' }).Count -gt 0
    $hasWHFB = ($userMethods | Where-Object { $_.MethodType -eq 'Windows Hello for Business' }).Count -gt 0
    $hasSMS = ($userMethods | Where-Object { $_.MethodType -eq 'Phone/SMS' }).Count -gt 0
    $hasEmail = ($userMethods | Where-Object { $_.MethodType -eq 'Email OTP' }).Count -gt 0
    $hasTAP = ($userMethods | Where-Object { $_.MethodType -eq 'Temporary Access Pass' }).Count -gt 0
    $hasOATH = ($userMethods | Where-Object { $_.MethodType -eq 'Software OATH' }).Count -gt 0
    
    $userInfo = [PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        UserId = $user.UserId
        HighestNISTAAL = $user.HighestNISTAAL
        HasAuthenticator = $hasAuthenticator
        HasFIDO2 = $hasFIDO2
        HasWHFB = $hasWHFB
        HasSMS = $hasSMS
        HasEmail = $hasEmail
        HasTAP = $hasTAP
        HasOATH = $hasOATH
        TotalAuthMethods = [int]$user.TotalAuthMethods
        CurrentlyPasswordless = $user.HasPasswordless -eq 'True'
        PhishingResistant = $user.HasPhishingResistant -eq 'True'
        WeakMethodCount = $(if($hasSMS){1}else{0}) + $(if($hasEmail){1}else{0})
        StrongMethodCount = $(if($hasAuthenticator){1}else{0}) + $(if($hasFIDO2){1}else{0}) + $(if($hasWHFB){1}else{0})
    }
    
    # Risk Assessment
    if ($userInfo.WeakMethodCount -gt 0 -and $userInfo.StrongMethodCount -eq 0) {
        $riskLevels.Critical += $userInfo
        $userInfo | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue "CRITICAL" -Force
    }
    elseif ($userInfo.WeakMethodCount -gt 0 -and $userInfo.StrongMethodCount -eq 1) {
        $riskLevels.High += $userInfo
        $userInfo | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue "HIGH" -Force
    }
    elseif ($userInfo.WeakMethodCount -gt 0 -and $userInfo.StrongMethodCount -gt 1) {
        $riskLevels.Medium += $userInfo
        $userInfo | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue "MEDIUM" -Force
    }
    else {
        $riskLevels.Low += $userInfo
        $userInfo | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue "LOW" -Force
    }
    
    # Migration Categories
    if ($hasAuthenticator -and -not $hasSMS -and -not $hasEmail) {
        $userCategories.AlreadyPasswordless += $userInfo
        $userInfo | Add-Member -NotePropertyName "MigrationCategory" -NotePropertyValue "ALREADY_PASSWORDLESS" -Force
    }
    elseif ($hasAuthenticator) {
        $userCategories.ReadyForPasswordless += $userInfo
        $userInfo | Add-Member -NotePropertyName "MigrationCategory" -NotePropertyValue "READY_FOR_PASSWORDLESS" -Force
        
        # Good pilot candidates: have authenticator + weak methods + not too many methods
        if (($hasSMS -or $hasEmail) -and $userInfo.TotalAuthMethods -le 3) {
            $userCategories.PilotCandidates += $userInfo
        }
    }
    elseif ($hasFIDO2 -or $hasWHFB) {
        $userCategories.AlreadyPasswordless += $userInfo
        $userInfo | Add-Member -NotePropertyName "MigrationCategory" -NotePropertyValue "ALREADY_STRONG_PASSWORDLESS" -Force
    }
    else {
        $userCategories.NeedsAuthenticator += $userInfo
        $userInfo | Add-Member -NotePropertyName "MigrationCategory" -NotePropertyValue "NEEDS_AUTHENTICATOR" -Force
        
        # High risk users need immediate attention
        if (($hasSMS -or $hasEmail) -and -not $hasAuthenticator -and -not $hasFIDO2 -and -not $hasWHFB) {
            $userCategories.HighRisk += $userInfo
        }
    }
}

# Generate migration waves based on risk and readiness
Write-Host "📋 Generating migration wave recommendations..." -ForegroundColor Green

# Select optimal pilot group (users with Authenticator + weak methods)
$optimalPilots = $userCategories.PilotCandidates | Sort-Object TotalAuthMethods | Select-Object -First $PilotGroupSize

$migrationWaves = @{
    Wave0_Analysis = @{
        Users = $complianceData
        Description = "Complete current state analysis and planning"
        Timeline = "Week 1"
        Actions = @("Analyze audit data", "Plan migration waves", "Prepare communications")
    }
    Wave1_Pilot = @{
        Users = $optimalPilots
        Description = "Pilot group with Authenticator app already registered"
        Timeline = "Week 2-3"
        Actions = @("Disable SMS/Email for pilot users", "Monitor for issues", "Gather feedback")
    }
    Wave2_ReadyUsers = @{
        Users = $userCategories.ReadyForPasswordless | Where-Object { $_.UserPrincipalName -notin $optimalPilots.UserPrincipalName }
        Description = "Users with Authenticator app ready for passwordless"
        Timeline = "Week 4-6"
        Actions = @("Bulk disable SMS/Email", "Monitor authentication patterns", "User support")
    }
    Wave3_HighRisk = @{
        Users = $userCategories.HighRisk
        Description = "CRITICAL: Users with only SMS/Email methods"
        Timeline = "Week 7-8"
        Actions = @("Force Authenticator registration", "Immediate migration", "Intensive support")
    }
    Wave4_Remaining = @{
        Users = $userCategories.NeedsAuthenticator | Where-Object { $_.UserPrincipalName -notin $userCategories.HighRisk.UserPrincipalName }
        Description = "Remaining users needing Authenticator deployment"
        Timeline = "Week 9-12"
        Actions = @("Authenticator deployment", "Training sessions", "Final migration")
    }
}

# Generate comprehensive reports
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# 1. Migration Wave Summary
$wavesSummary = @()
foreach ($waveKey in $migrationWaves.Keys) {
    $wave = $migrationWaves[$waveKey]
    $wavesSummary += [PSCustomObject]@{
        Wave = $waveKey
        Description = $wave.Description
        Timeline = $wave.Timeline
        UserCount = $wave.Users.Count
        Actions = ($wave.Actions -join '; ')
    }
}

$wavesSummaryPath = Join-Path -Path $ExportPath -ChildPath "PasswordlessMigration_Waves_$timestamp.csv"
$wavesSummary | Export-Csv -Path $wavesSummaryPath -NoTypeInformation -Encoding UTF8

# 2. Risk Assessment Report
$riskAssessment = @()
foreach ($riskLevel in $riskLevels.Keys) {
    $users = $riskLevels[$riskLevel]
    $riskAssessment += [PSCustomObject]@{
        RiskLevel = $riskLevel
        UserCount = $users.Count
        Description = switch ($riskLevel) {
            "Critical" { "Users with only SMS/Email - IMMEDIATE ACTION REQUIRED" }
            "High" { "Users with SMS/Email + minimal strong methods" }
            "Medium" { "Users with mixed strong/weak methods" }
            "Low" { "Users with only strong authentication methods" }
        }
        RecommendedAction = switch ($riskLevel) {
            "Critical" { "Force immediate Authenticator registration + training" }
            "High" { "Priority Authenticator deployment + disable weak methods" }
            "Medium" { "Planned weak method removal after verification" }
            "Low" { "Monitor and maintain current security posture" }
        }
        PercentageOfTotal = [math]::Round(($users.Count / $complianceData.Count) * 100, 2)
    }
}

$riskAssessmentPath = Join-Path -Path $ExportPath -ChildPath "PasswordlessMigration_RiskAssessment_$timestamp.csv"
$riskAssessment | Export-Csv -Path $riskAssessmentPath -NoTypeInformation -Encoding UTF8

# 3. Detailed User Analysis
$allUsersAnalysis = @()
foreach ($user in $complianceData) {
    $userMethods = $authMethods | Where-Object { $_.UserPrincipalName -eq $user.UserPrincipalName }
    $methodsList = ($userMethods | ForEach-Object { $_.MethodType }) -join '; '
    
    # Find user in categories
    $category = "UNKNOWN"
    $risk = "UNKNOWN"
    
    foreach ($catKey in $userCategories.Keys) {
        if ($user.UserPrincipalName -in $userCategories[$catKey].UserPrincipalName) {
            $userDetail = $userCategories[$catKey] | Where-Object { $_.UserPrincipalName -eq $user.UserPrincipalName }
            if ($userDetail) {
                $category = $userDetail.MigrationCategory
                $risk = $userDetail.RiskLevel
                break
            }
        }
    }
    
    $allUsersAnalysis += [PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        CurrentAuthMethods = $methodsList
        MigrationCategory = $category
        RiskLevel = $risk
        HighestNISTAAL = $user.HighestNISTAAL
        HasPasswordless = $user.HasPasswordless
        HasPhishingResistant = $user.HasPhishingResistant
        TotalMethods = $user.TotalAuthMethods
        RecommendedAction = switch ($category) {
            "ALREADY_PASSWORDLESS" { "No action needed - monitor" }
            "READY_FOR_PASSWORDLESS" { "Disable SMS/Email methods" }
            "NEEDS_AUTHENTICATOR" { "Deploy Authenticator app first" }
            default { "Requires assessment" }
        }
        MigrationWave = if ($user.UserPrincipalName -in $optimalPilots.UserPrincipalName) { "Wave1_Pilot" }
                       elseif ($user.UserPrincipalName -in $migrationWaves.Wave2_ReadyUsers.Users.UserPrincipalName) { "Wave2_ReadyUsers" }
                       elseif ($user.UserPrincipalName -in $migrationWaves.Wave3_HighRisk.Users.UserPrincipalName) { "Wave3_HighRisk" }
                       elseif ($user.UserPrincipalName -in $migrationWaves.Wave4_Remaining.Users.UserPrincipalName) { "Wave4_Remaining" }
                       else { "Wave0_Analysis" }
    }
}

$userAnalysisPath = Join-Path -Path $ExportPath -ChildPath "PasswordlessMigration_UserAnalysis_$timestamp.csv"
$allUsersAnalysis | Export-Csv -Path $userAnalysisPath -NoTypeInformation -Encoding UTF8

# 4. Executive Summary
$executiveSummary = [PSCustomObject]@{
    TotalUsers = $complianceData.Count
    AlreadyPasswordless = $userCategories.AlreadyPasswordless.Count
    ReadyForMigration = $userCategories.ReadyForPasswordless.Count
    NeedsAuthenticator = $userCategories.NeedsAuthenticator.Count
    HighRiskUsers = $userCategories.HighRisk.Count
    PilotGroupSize = $optimalPilots.Count
    EstimatedMigrationWeeks = 12
    CriticalRiskPercentage = [math]::Round(($riskLevels.Critical.Count / $complianceData.Count) * 100, 2)
    PasswordlessReadyPercentage = [math]::Round((($userCategories.AlreadyPasswordless.Count + $userCategories.ReadyForPasswordless.Count) / $complianceData.Count) * 100, 2)
    RecommendedStartDate = (Get-Date).AddDays(7).ToString('yyyy-MM-dd')
    RecommendedCompletionDate = (Get-Date).AddDays(84).ToString('yyyy-MM-dd')
}

$executiveSummaryPath = Join-Path -Path $ExportPath -ChildPath "PasswordlessMigration_ExecutiveSummary_$timestamp.csv"
$executiveSummary | Export-Csv -Path $executiveSummaryPath -NoTypeInformation -Encoding UTF8

# Display summary
Write-Host "`n🎯 PASSWORDLESS MFA MIGRATION ANALYSIS COMPLETE" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Green

Write-Host "`n📊 Current State Summary:" -ForegroundColor Cyan
Write-Host "  Total Users: $($complianceData.Count)" -ForegroundColor White
Write-Host "  Already Passwordless: $($userCategories.AlreadyPasswordless.Count) ($([math]::Round(($userCategories.AlreadyPasswordless.Count / $complianceData.Count) * 100, 1))%)" -ForegroundColor Green
Write-Host "  Ready for Migration: $($userCategories.ReadyForPasswordless.Count) ($([math]::Round(($userCategories.ReadyForPasswordless.Count / $complianceData.Count) * 100, 1))%)" -ForegroundColor Yellow
Write-Host "  Needs Authenticator: $($userCategories.NeedsAuthenticator.Count) ($([math]::Round(($userCategories.NeedsAuthenticator.Count / $complianceData.Count) * 100, 1))%)" -ForegroundColor Orange
Write-Host "  HIGH RISK (SMS/Email only): $($userCategories.HighRisk.Count) ($([math]::Round(($userCategories.HighRisk.Count / $complianceData.Count) * 100, 1))%)" -ForegroundColor Red

Write-Host "`n🚨 Risk Distribution:" -ForegroundColor Cyan
Write-Host "  Critical Risk: $($riskLevels.Critical.Count) users" -ForegroundColor Red
Write-Host "  High Risk: $($riskLevels.High.Count) users" -ForegroundColor Yellow
Write-Host "  Medium Risk: $($riskLevels.Medium.Count) users" -ForegroundColor Green
Write-Host "  Low Risk: $($riskLevels.Low.Count) users" -ForegroundColor Green

Write-Host "`n📋 Migration Waves:" -ForegroundColor Cyan
Write-Host "  Wave 1 (Pilot): $($optimalPilots.Count) users" -ForegroundColor Green
Write-Host "  Wave 2 (Ready): $($migrationWaves.Wave2_ReadyUsers.Users.Count) users" -ForegroundColor Green
Write-Host "  Wave 3 (High Risk): $($migrationWaves.Wave3_HighRisk.Users.Count) users" -ForegroundColor Red
Write-Host "  Wave 4 (Remaining): $($migrationWaves.Wave4_Remaining.Users.Count) users" -ForegroundColor Yellow

Write-Host "`n📁 Reports Generated:" -ForegroundColor Cyan
Write-Host "  Migration Waves: $wavesSummaryPath" -ForegroundColor White
Write-Host "  Risk Assessment: $riskAssessmentPath" -ForegroundColor White
Write-Host "  User Analysis: $userAnalysisPath" -ForegroundColor White
Write-Host "  Executive Summary: $executiveSummaryPath" -ForegroundColor White

Write-Host "`n✅ Next Steps:" -ForegroundColor Green
Write-Host "  1. Review executive summary and risk assessment" -ForegroundColor White
Write-Host "  2. Prepare pilot group communications" -ForegroundColor White
Write-Host "  3. Plan Authenticator app deployment for high-risk users" -ForegroundColor White
Write-Host "  4. Schedule migration waves based on timeline" -ForegroundColor White

if ($userCategories.HighRisk.Count -gt 0) {
    Write-Host "`n⚠️  URGENT: $($userCategories.HighRisk.Count) users have only SMS/Email authentication!" -ForegroundColor Red
    Write-Host "   These users require immediate Authenticator deployment before SMS/Email can be disabled." -ForegroundColor Red
}

Write-Host "`nPasswordless migration analysis completed successfully! 🎉" -ForegroundColor Green