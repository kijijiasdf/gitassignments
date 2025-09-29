#Requires -Version 5.1
<#
.SYNOPSIS
    Unified script to update guest user attributes (UPN, Mail, MailNickname) in Azure Entra ID across multiple tenants.
    
.DESCRIPTION
    This consolidated script processes CSV files of guest users and updates their attributes by replacing old domain strings with new ones.
    Supports single or multiple attribute updates with comprehensive logging and multi-tenant operations.
    
    Features:
    - Multi-attribute support: UPN, Mail, MailNickname
    - Multi-tenant operations with tenant switching
    - PowerShell 5.1 compatible
    - Comprehensive error handling and logging
    - Dry-run mode for safe testing
    - Results export with detailed status tracking
    - Guest user validation and domain preservation
    
.PARAMETER CsvPath
    Path to CSV file containing user information (ObjectId or UserPrincipalName columns required)
    
.PARAMETER UpdateType
    Type of attribute update to perform:
    - UPN: Updates UserPrincipalName only
    - Mail: Updates Mail attribute only  
    - MailNickname: Updates MailNickname only
    - All: Updates all three attributes
    
.PARAMETER SearchDomain
    Domain string to replace in the specified attributes (e.g., "pf-gt.com")
    
.PARAMETER NewDomain
    New domain string to use as replacement (e.g., "pf.gt.com")
    
.PARAMETER TenantIds
    Array of Azure tenant IDs to process. Can specify multiple tenants for cross-tenant operations.
    
.PARAMETER BatchSize
    Number of users to process in each batch (default: 10)
    
.PARAMETER RealMode
    Switch to enable actual changes. Without this, script runs in dry-run mode.
    
.PARAMETER ExportPath
    Directory to save results files (default: current directory)
    
.EXAMPLE
    .\Update-GuestUserAttributes-Unified.ps1 -CsvPath "users.csv" -UpdateType "MailNickname" -SearchDomain "pf-gt.com" -NewDomain "pf.gt.com" -TenantIds @("tenant1-id")
    
.EXAMPLE
    .\Update-GuestUserAttributes-Unified.ps1 -CsvPath "users.csv" -UpdateType "All" -SearchDomain "old.com" -NewDomain "new.com" -TenantIds @("tenant1-id", "tenant2-id") -RealMode
    
.NOTES
    Author: Azure Identity Management Scripts
    Version: 1.0
    
    Requirements:
    - PowerShell 5.1+
    - Microsoft.Graph.Users module
    - Microsoft.Graph.Authentication module
    - User.ReadWrite.All permission scope
    
    Compatible with: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet('UPN', 'Mail', 'MailNickname', 'All')]
    [string]$UpdateType,
    
    [Parameter(Mandatory = $false)]
    [string]$SearchDomain,
    
    [Parameter(Mandatory = $false)]
    [string]$NewDomain,
    
    [Parameter(Mandatory = $false)]
    [string[]]$TenantIds,
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 50)]
    [int]$BatchSize = 10,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory = $false)]
    [switch]$RealMode
)

# Required modules
$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Users'
)

# Global counters
$Global:ProcessedUsers = 0
$Global:UpdatedUsers = 0
$Global:SkippedUsers = 0
$Global:ErrorCount = 0
$Global:AllResults = @()

function Write-UnifiedLog {
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
    Write-UnifiedLog "Validating required modules..." -Level 'Info'
    
    foreach ($module in $RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-UnifiedLog "❌ Module not found: $module" -Level 'Error'
            Write-UnifiedLog "Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -Level 'Error'
            throw "Required module $module is not available"
        } else {
            Write-UnifiedLog "✅ Module available: $module" -Level 'Success'
        }
    }
    
    # Import modules
    foreach ($module in $RequiredModules) {
        try {
            Import-Module -Name $module -Force -ErrorAction Stop
            Write-UnifiedLog "✅ Module imported: $module" -Level 'Success'
        }
        catch {
            Write-UnifiedLog "❌ Failed to import module: $module" -Level 'Error'
            throw "Could not import required module $module"
        }
    }
}

function Connect-ToTenant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )
    
    try {
        Write-UnifiedLog "Connecting to Microsoft Graph for tenant: $TenantId" -Level 'Info'
        
        # Check if already connected to this tenant
        $currentContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($currentContext -and $currentContext.TenantId -eq $TenantId) {
            Write-UnifiedLog "✅ Already connected to target tenant: $TenantId" -Level 'Success'
            return $true
        }
        
        # Connect to new tenant
        Connect-MgGraph -TenantId $TenantId -Scopes @('User.ReadWrite.All') -ErrorAction Stop
        $newContext = Get-MgContext
        Write-UnifiedLog "✅ Connected to tenant: $($newContext.TenantId)" -Level 'Success'
        
        return $true
    }
    catch {
        Write-UnifiedLog "❌ Failed to connect to tenant $TenantId`: $($_.Exception.Message)" -Level 'Error'
        return $false
    }
}

function Get-TenantDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )
    
    try {
        $domains = Get-MgDomain -ErrorAction Stop
        $tenantDomain = ($domains | Where-Object { $_.Id -like "*.onmicrosoft.com" }).Id | Select-Object -First 1
        
        if ($tenantDomain) {
            Write-UnifiedLog "📍 Tenant domain: $tenantDomain" -Level 'Info'
            return $tenantDomain
        } else {
            throw "Could not determine tenant domain"
        }
    }
    catch {
        Write-UnifiedLog "❌ Failed to get tenant domain: $($_.Exception.Message)" -Level 'Error'
        throw
    }
}

function Update-UserAttribute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,
        
        [Parameter(Mandatory = $true)]
        [string]$AttributeType,
        
        [Parameter(Mandatory = $true)]
        [string]$SearchDomain,
        
        [Parameter(Mandatory = $true)]
        [string]$NewDomain,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantDomain,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $result = @{
        Success = $false
        OldValue = ""
        NewValue = ""
        Action = "Skipped"
        Error = ""
    }
    
    try {
        switch ($AttributeType) {
            'UPN' {
                $currentUPN = $User.UserPrincipalName
                $upnPrefix = $currentUPN.Split("@")[0]
                $newPrefix = $upnPrefix -replace [regex]::Escape($SearchDomain), $NewDomain
                $newUPN = "$newPrefix@$TenantDomain"
                
                $result.OldValue = $currentUPN
                $result.NewValue = $newUPN
                
                if ($currentUPN -eq $newUPN) {
                    $result.Action = "No change needed"
                    return $result
                }
                
                if (-not $DryRun) {
                    Update-MgUser -UserId $User.Id -UserPrincipalName $newUPN -ErrorAction Stop
                    
                    # Verify change
                    Start-Sleep -Seconds 2
                    $verifyUser = Get-MgUser -UserId $User.Id -Property "UserPrincipalName" -ErrorAction Stop
                    $result.NewValue = $verifyUser.UserPrincipalName
                    $result.Action = "Updated"
                } else {
                    $result.Action = "DryRun"
                }
                
                $result.Success = $true
            }
            
            'Mail' {
                $currentMail = $User.Mail
                if ([string]::IsNullOrEmpty($currentMail)) {
                    $result.Action = "No Mail attribute"
                    return $result
                }
                
                if ($currentMail -match "^(.*)@(.+)$") {
                    $mailUser = $Matches[1]
                    $mailDomain = $Matches[2] -replace [regex]::Escape($SearchDomain), $NewDomain
                    $newMail = "$mailUser@$mailDomain"
                } else {
                    $result.Action = "Invalid Mail format"
                    return $result
                }
                
                $result.OldValue = $currentMail
                $result.NewValue = $newMail
                
                if ($currentMail -eq $newMail) {
                    $result.Action = "No change needed"
                    return $result
                }
                
                if (-not $DryRun) {
                    Update-MgUser -UserId $User.Id -Mail $newMail -ErrorAction Stop
                    
                    # Verify change
                    Start-Sleep -Seconds 2
                    $verifyUser = Get-MgUser -UserId $User.Id -Property "Mail" -ErrorAction Stop
                    $result.NewValue = $verifyUser.Mail
                    $result.Action = "Updated"
                } else {
                    $result.Action = "DryRun"
                }
                
                $result.Success = $true
            }
            
            'MailNickname' {
                $currentMailNick = $User.MailNickname
                if ([string]::IsNullOrEmpty($currentMailNick) -or $currentMailNick -notlike "*$SearchDomain*") {
                    $result.Action = "No matching MailNickname"
                    return $result
                }
                
                $newMailNick = $currentMailNick -replace [regex]::Escape($SearchDomain), $NewDomain
                
                $result.OldValue = $currentMailNick
                $result.NewValue = $newMailNick
                
                if ($currentMailNick -eq $newMailNick) {
                    $result.Action = "No change needed"
                    return $result
                }
                
                if (-not $DryRun) {
                    Update-MgUser -UserId $User.Id -MailNickname $newMailNick -ErrorAction Stop
                    
                    # Verify change
                    Start-Sleep -Seconds 2
                    $verifyUser = Get-MgUser -UserId $User.Id -Property "MailNickname" -ErrorAction Stop
                    $result.NewValue = $verifyUser.MailNickname
                    $result.Action = "Updated"
                } else {
                    $result.Action = "DryRun"
                }
                
                $result.Success = $true
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Action = "Failed"
    }
    
    return $result
}

function Process-UserBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$UserBatch,
        
        [Parameter(Mandatory = $true)]
        [string]$UpdateType,
        
        [Parameter(Mandatory = $true)]
        [string]$SearchDomain,
        
        [Parameter(Mandatory = $true)]
        [string]$NewDomain,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantDomain,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $batchResults = @()
    
    foreach ($row in $UserBatch) {
        $Global:ProcessedUsers++
        
        # Get user identifier
        $userId = $row.ObjectId
        if (-not $userId) { $userId = $row.UserPrincipalName }
        if (-not $userId) { 
            Write-UnifiedLog "[$Global:ProcessedUsers] No ObjectId or UPN found - skipping" -Level 'Warning'
            $Global:SkippedUsers++
            continue 
        }
        
        Write-UnifiedLog "[$Global:ProcessedUsers] Processing: $userId" -Level 'Info'
        
        try {
            # Get user details
            $user = Get-MgUser -UserId $userId -Property "Id,UserPrincipalName,Mail,MailNickname,DisplayName,UserType" -ErrorAction Stop
            
            # Verify guest user
            if ($user.UserType -ne "Guest") {
                Write-UnifiedLog "  SKIP: Not a guest user ($($user.UserType))" -Level 'Warning'
                $Global:SkippedUsers++
                continue
            }
            
            # Process attributes based on UpdateType
            $attributesToUpdate = switch ($UpdateType) {
                'UPN' { @('UPN') }
                'Mail' { @('Mail') }
                'MailNickname' { @('MailNickname') }
                'All' { @('UPN', 'Mail', 'MailNickname') }
            }
            
            $userUpdated = $false
            $userResults = @()
            
            foreach ($attribute in $attributesToUpdate) {
                Write-UnifiedLog "    Processing $attribute..." -Level 'Info'
                
                $updateResult = Update-UserAttribute -User $user -AttributeType $attribute -SearchDomain $SearchDomain -NewDomain $NewDomain -TenantDomain $TenantDomain -DryRun:$DryRun
                
                if ($updateResult.Success -and $updateResult.Action -eq "Updated") {
                    $userUpdated = $true
                    Write-UnifiedLog "    ✅ $attribute`: $($updateResult.OldValue) → $($updateResult.NewValue)" -Level 'Success'
                } elseif ($updateResult.Action -eq "DryRun") {
                    Write-UnifiedLog "    🧪 $attribute`: $($updateResult.OldValue) → $($updateResult.NewValue) [DRY RUN]" -Level 'Info'
                } elseif ($updateResult.Action -eq "No change needed") {
                    Write-UnifiedLog "    ⏭️ $attribute`: No change needed" -Level 'Info'
                } else {
                    Write-UnifiedLog "    ⚠️ $attribute`: $($updateResult.Action)" -Level 'Warning'
                    if ($updateResult.Error) {
                        Write-UnifiedLog "    ❌ Error: $($updateResult.Error)" -Level 'Error'
                        $Global:ErrorCount++
                    }
                }
                
                # Store individual attribute result
                $userResults += [PSCustomObject]@{
                    TenantId = $TenantId
                    ObjectId = $user.Id
                    DisplayName = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    AttributeType = $attribute
                    OldValue = $updateResult.OldValue
                    NewValue = $updateResult.NewValue
                    Action = $updateResult.Action
                    Success = $updateResult.Success
                    Error = $updateResult.Error
                    Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
            }
            
            if ($userUpdated) {
                $Global:UpdatedUsers++
            }
            
            $batchResults += $userResults
            
        }
        catch {
            Write-UnifiedLog "  ❌ Failed to process user $userId`: $($_.Exception.Message)" -Level 'Error'
            $Global:ErrorCount++
            
            # Log error result
            $batchResults += [PSCustomObject]@{
                TenantId = $TenantId
                ObjectId = $userId
                DisplayName = "Unknown"
                UserPrincipalName = $userId
                AttributeType = "Error"
                OldValue = ""
                NewValue = ""
                Action = "Failed"
                Success = $false
                Error = $_.Exception.Message
                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            }
        }
    }
    
    return $batchResults
}

function Start-GuestUserAttributeUpdate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [array]$Users,
        
        [Parameter(Mandatory = $true)]
        [string]$UpdateType,
        
        [Parameter(Mandatory = $true)]
        [string]$SearchDomain,
        
        [Parameter(Mandatory = $true)]
        [string]$NewDomain,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    $updateStartTime = Get-Date
    
    Write-UnifiedLog "🚀 Starting $UpdateType attribute update for tenant: $TenantId" -Level 'Success'
    Write-UnifiedLog "📊 Processing $($Users.Count) users in batches of $BatchSize" -Level 'Info'
    
    # Connect to tenant
    if (-not (Connect-ToTenant -TenantId $TenantId)) {
        throw "Failed to connect to tenant $TenantId"
    }
    
    # Get tenant domain (needed for UPN updates)
    $tenantDomain = $null
    if ($UpdateType -eq 'UPN' -or $UpdateType -eq 'All') {
        $tenantDomain = Get-TenantDomain -TenantId $TenantId
    }
    
    # Process users in batches
    $batchNumber = 1
    $totalBatches = [math]::Ceiling($Users.Count / $BatchSize)
    $tenantResults = @()
    
    for ($i = 0; $i -lt $Users.Count; $i += $BatchSize) {
        $batchEndIndex = [math]::Min($i + $BatchSize - 1, $Users.Count - 1)
        $currentBatch = $Users[$i..$batchEndIndex]
        
        $batchStartTime = Get-Date
        Write-UnifiedLog "📦 Processing batch $batchNumber/$totalBatches ($($currentBatch.Count) users)..." -Level 'Info'
        
        $batchResults = Process-UserBatch -UserBatch $currentBatch -UpdateType $UpdateType -SearchDomain $SearchDomain -NewDomain $NewDomain -TenantId $TenantId -TenantDomain $tenantDomain -DryRun:$DryRun
        
        $tenantResults += $batchResults
        
        $batchTime = ((Get-Date) - $batchStartTime).TotalSeconds
        Write-UnifiedLog "✅ Batch $batchNumber completed in $([math]::Round($batchTime, 1)) seconds" -Level 'Success'
        
        $batchNumber++
        
        # Small delay between batches
        if ($batchNumber -le $totalBatches) {
            Start-Sleep -Milliseconds 500
        }
    }
    
    $totalTime = (Get-Date) - $updateStartTime
    Write-UnifiedLog "🎉 Tenant $TenantId completed in $([math]::Round($totalTime.TotalMinutes, 1)) minutes" -Level 'Success'
    
    return $tenantResults
}

# Main execution
try {
    Write-UnifiedLog "🚀 Azure Guest User Attributes Update - Unified Script" -Level 'Success'
    Write-UnifiedLog ("=" * 60) -Level 'Success'
    
    # Validate inputs
    if (-not (Test-Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }
    
    # Get interactive parameters if not provided
    if (-not $TenantIds) {
        $tenantInput = Read-Host "Enter Azure Tenant ID(s) (comma-separated for multiple)"
        $TenantIds = $tenantInput -split ',' | ForEach-Object { $_.Trim() }
    }
    
    if (-not $SearchDomain) {
        $SearchDomain = Read-Host "Enter the domain string to replace (e.g., pf-gt.com)"
    }
    
    if (-not $NewDomain) {
        $NewDomain = Read-Host "Enter the new domain string (e.g., pf.gt.com)"
    }
    
    # Validate domain inputs
    if ([string]::IsNullOrWhiteSpace($SearchDomain) -or [string]::IsNullOrWhiteSpace($NewDomain)) {
        throw "SearchDomain and NewDomain cannot be empty"
    }
    
    if ($SearchDomain -eq $NewDomain) {
        throw "SearchDomain and NewDomain cannot be identical"
    }
    
    # Display configuration
    Write-UnifiedLog "📋 Configuration:" -Level 'Info'
    Write-UnifiedLog "   Update Type: $UpdateType" -Level 'Info'
    Write-UnifiedLog "   Search Domain: $SearchDomain" -Level 'Info'
    Write-UnifiedLog "   New Domain: $NewDomain" -Level 'Info'
    Write-UnifiedLog "   Tenants: $($TenantIds -join ', ')" -Level 'Info'
    Write-UnifiedLog "   Mode: $(if($RealMode){'LIVE CHANGES'}else{'DRY RUN'})" -Level $(if($RealMode){'Error'}else{'Warning'})
    Write-UnifiedLog "   Batch Size: $BatchSize" -Level 'Info'
    Write-UnifiedLog "" -Level 'Info'
    
    # Test module availability
    Test-ModuleAvailability
    
    # Import and validate CSV
    try {
        $users = Import-Csv -Path $CsvPath
        Write-UnifiedLog "📄 Loaded $($users.Count) users from CSV" -Level 'Success'
    }
    catch {
        throw "Failed to import CSV: $($_.Exception.Message)"
    }
    
    # Validate CSV has required columns
    $firstUser = $users | Select-Object -First 1
    if (-not ($firstUser.PSObject.Properties.Name -contains "ObjectId" -or $firstUser.PSObject.Properties.Name -contains "UserPrincipalName")) {
        throw "CSV must contain either 'ObjectId' or 'UserPrincipalName' column"
    }
    
    # Process each tenant
    foreach ($tenantId in $TenantIds) {
        Write-UnifiedLog "`n🏢 Processing tenant: $tenantId" -Level 'Info'
        
        try {
            $tenantResults = Start-GuestUserAttributeUpdate -TenantId $tenantId -Users $users -UpdateType $UpdateType -SearchDomain $SearchDomain -NewDomain $NewDomain -DryRun:(-not $RealMode)
            
            $Global:AllResults += $tenantResults
            
            Write-UnifiedLog "✅ Tenant $tenantId completed successfully" -Level 'Success'
        }
        catch {
            Write-UnifiedLog "❌ Tenant $tenantId failed: $($_.Exception.Message)" -Level 'Error'
            $Global:ErrorCount++
        }
    }
    
    # Generate summary
    Write-UnifiedLog "`n📊 FINAL SUMMARY" -Level 'Success'
    Write-UnifiedLog ("=" * 60) -Level 'Success'
    Write-UnifiedLog "Total Processed: $Global:ProcessedUsers" -Level 'Info'
    Write-UnifiedLog "Successfully Updated: $Global:UpdatedUsers" -Level 'Success'
    Write-UnifiedLog "Skipped: $Global:SkippedUsers" -Level 'Warning'
    Write-UnifiedLog "Errors: $Global:ErrorCount" -Level 'Error'
    
    # Export results
    if ($Global:AllResults.Count -gt 0) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $resultsPath = Join-Path $ExportPath "GuestUserUpdate_${UpdateType}_${timestamp}.csv"
        
        $Global:AllResults | Export-Csv -Path $resultsPath -NoTypeInformation -Encoding UTF8
        Write-UnifiedLog "`n📁 Results exported to: $resultsPath" -Level 'Success'
    }
    
    Write-UnifiedLog "`n🎊 Guest User Attribute Update completed successfully!" -Level 'Success'
    
}
catch {
    Write-UnifiedLog "❌ Script execution failed: $($_.Exception.Message)" -Level 'Error'
    Write-UnifiedLog "Stack trace: $($_.ScriptStackTrace)" -Level 'Error'
    exit 1
}
finally {
    # Clean disconnect
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Ignore disconnect errors
    }
}