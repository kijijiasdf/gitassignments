<#
.SYNOPSIS
    Multi-Tenant Azure AD Authentication Methods Audit (Read-Only)

.DESCRIPTION
    Connects to one or more Azure tenants via Microsoft Graph,
    inventories every member user's registered auth methods (weak and phishing-resistant),
    and exports detailed CSV reports and summary statistics.

.PARAMETER TenantID
    Array of Azure Tenant IDs to audit.

.PARAMETER ExportPath
    Directory to save CSV reports (default: current folder).

.PARAMETER BatchSize
    Number of users to process in parallel batches (default: 50).

.PARAMETER LogLevel
    Logging level: Error, Warning, Information, Verbose, Debug (default: Information).

.EXAMPLE
    .\Audit-AzureAuthMethods.ps1 -TenantID "tenant1","tenant2" -ExportPath "C:\Reports" -Verbose

.EXAMPLE
    .\Audit-AzureAuthMethods.ps1 -TenantID "tenant1" -BatchSize 100 -LogLevel Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = "Array of Azure Tenant IDs to audit")]
    [ValidateNotNullOrEmpty()]
    [string[]]$TenantID,
    
    [Parameter(HelpMessage = "Directory to save CSV reports")]
    [ValidateNotNullOrEmpty()]
    [string]$ExportPath = $PWD,
    
    [Parameter(HelpMessage = "Number of users to process in parallel batches")]
    [ValidateRange(1, 200)]
    [int]$BatchSize = 50,
    
    [Parameter(HelpMessage = "Logging level")]
    [ValidateSet("Error", "Warning", "Information", "Verbose", "Debug")]
    [string]$LogLevel = "Information"
)

# Script configuration
$ScriptConfig = @{
    RequiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Policies')
    MaxRetries = 3
    RetryDelaySeconds = 5
    TimeoutSeconds = 300
}

# Enhanced logging function
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Error", "Warning", "Information", "Verbose", "Debug")]
        [string]$Level = "Information",
        
        [Parameter()]
        [string]$TenantId = "Global"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$TenantId] [$Level] $Message"
    
    switch ($Level) {
        "Error"   { Write-Error $logMessage -ErrorAction Continue }
        "Warning" { Write-Warning $logMessage }
        "Information" { Write-Host $logMessage -ForegroundColor White }
        "Verbose" { Write-Verbose $logMessage }
        "Debug"   { Write-Debug $logMessage }
    }
    
    # Also write to transcript if available
    if ($Host.UI.RawUI.WindowTitle -match "Transcript") {
        $logMessage | Out-File -FilePath "Transcript.log" -Append -Encoding UTF8
    }
}

# Enhanced error handling with retry logic
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        [int]$MaxRetries = $ScriptConfig.MaxRetries,
        
        [Parameter()]
        [int]$DelaySeconds = $ScriptConfig.RetryDelaySeconds,
        
        [Parameter()]
        [string]$OperationName = "Operation"
    )
    
    $attempt = 1
    do {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($attempt -le $MaxRetries) {
                Write-Log "Attempt $attempt of $MaxRetries failed for $OperationName. Error: $($_.Exception.Message)" -Level Warning
                if ($attempt -lt $MaxRetries) {
                    Write-Log "Retrying in $DelaySeconds seconds..." -Level Information
                    Start-Sleep -Seconds $DelaySeconds
                }
                $attempt++
            }
            else {
                Write-Log "All $MaxRetries attempts failed for $OperationName. Final error: $($_.Exception.Message)" -Level Error
                throw
            }
        }
    } while ($attempt -le $MaxRetries)
}

# Enhanced module management
function Initialize-RequiredModules {
    Write-Log "Initializing required PowerShell modules..." -Level Information
    
    foreach ($module in $ScriptConfig.RequiredModules) {
        try {
            if (-not (Get-Module -ListAvailable $module)) {
                Write-Log "Installing module: $module" -Level Information
                Install-Module $module -Force -Scope CurrentUser -ErrorAction Stop
            }
            
            if (-not (Get-Module $module)) {
                Write-Log "Importing module: $module" -Level Information
                Import-Module $module -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Log "Failed to install/import module $module`: $($_.Exception.Message)" -Level Error
            throw "Module initialization failed for $module"
        }
    }
    
    Write-Log "All required modules initialized successfully" -Level Information
}

# Enhanced tenant connection with better error handling
function Connect-Tenant {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId
    )
    
    Write-Log "Connecting to tenant $TenantId..." -Level Information -TenantId $TenantId
    
    try {
        # Check if already connected to this tenant
        $context = Get-MgContext
        if ($context -and $context.TenantId -eq $TenantId) {
            Write-Log "Already connected to tenant $TenantId" -Level Information -TenantId $TenantId
            return $true
        }
        
        # Disconnect if connected to different tenant
        if ($context) {
            Write-Log "Disconnecting from current tenant to connect to $TenantId" -Level Information -TenantId $TenantId
            Disconnect-MgGraph
        }
        
        # Connect to target tenant
        $connectionResult = Invoke-WithRetry -ScriptBlock {
            Connect-MgGraph -TenantId $TenantId -Scopes @(
                'User.Read.All',
                'UserAuthenticationMethod.Read.All',
                'Policy.Read.All'
            ) -ErrorAction Stop
        } -OperationName "Connect-MgGraph for tenant $TenantId"
        
        Write-Log "Successfully connected to tenant $TenantId" -Level Information -TenantId $TenantId
        return $true
    }
    catch {
        Write-Log "Failed to connect to tenant $TenantId`: $($_.Exception.Message)" -Level Error -TenantId $TenantId
        throw
    }
}

# Enhanced authentication method mapping with better categorization
$MethodMap = @{
    Phone = @{ 
        Cmd = 'Get-MgUserAuthenticationPhoneMethod'
        Type = 'Phone/SMS'
        Weak = $true
        Strong = $false
        RiskLevel = 'High'
        Description = 'SMS-based authentication vulnerable to SIM swapping'
    }
    Email = @{ 
        Cmd = 'Get-MgUserAuthenticationEmailMethod'
        Type = 'Email OTP'
        Weak = $true
        Strong = $false
        RiskLevel = 'Medium'
        Description = 'Email-based OTP vulnerable to email compromise'
    }
    Fido2 = @{ 
        Cmd = 'Get-MgUserAuthenticationFido2Method'
        Type = 'FIDO2'
        Weak = $false
        Strong = $true
        RiskLevel = 'Low'
        Description = 'Hardware-based phishing-resistant authentication'
    }
    Authenticator = @{ 
        Cmd = 'Get-MgUserAuthenticationMicrosoftAuthenticatorMethod'
        Type = 'Microsoft Authenticator'
        Weak = $false
        Strong = $true
        RiskLevel = 'Low'
        Description = 'App-based phishing-resistant authentication'
    }
    Hello = @{ 
        Cmd = 'Get-MgUserAuthenticationWindowsHelloForBusinessMethod'
        Type = 'Windows Hello'
        Weak = $false
        Strong = $true
        RiskLevel = 'Low'
        Description = 'Biometric/physical key-based authentication'
    }
    TAP = @{ 
        Cmd = 'Get-MgUserAuthenticationTemporaryAccessPassMethod'
        Type = 'Temporary Access Pass'
        Weak = $false
        Strong = $false
        RiskLevel = 'Medium'
        Description = 'Temporary password for initial setup'
    }
    OATH = @{ 
        Cmd = 'Get-MgUserAuthenticationSoftwareOathMethod'
        Type = 'Software OATH'
        Weak = $false
        Strong = $false
        RiskLevel = 'Medium'
        Description = 'Time-based one-time password'
    }
}

# Enhanced user authentication methods retrieval with better error handling
function Get-UserMethods {
    param(
        [Parameter(Mandatory)]
        [string]$UserId,
        
        [Parameter(Mandatory)]
        [string]$UPN,
        
        [Parameter()]
        [string]$TenantId
    )
    
    $methods = @()
    
    foreach ($key in $MethodMap.Keys) {
        try {
            $list = Invoke-WithRetry -ScriptBlock {
                & $MethodMap[$key].Cmd -UserId $UserId -ErrorAction Stop
            } -OperationName "Get $($MethodMap[$key].Type) methods for user $UPN"
            
            foreach ($m in $list) {
                $detail = $null
                
                # Extract relevant details based on method type
                switch ($key) {
                    "Phone" { $detail = $m.PhoneNumber }
                    "Email" { $detail = $m.EmailAddress }
                    "Fido2" { $detail = $m.DisplayName -or $m.Model }
                    "Authenticator" { $detail = $m.DisplayName -or $m.DeviceTag }
                    "Hello" { $detail = $m.DisplayName }
                    "TAP" { $detail = "Expires: $($m.LifetimeInMinutes) minutes" }
                    "OATH" { $detail = $m.DisplayName }
                    default { $detail = $m.DisplayName -or $m.Id }
                }
                
                $methods += [PSCustomObject]@{
                    UserPrincipalName = $UPN
                    MethodType = $MethodMap[$key].Type
                    MethodId = $m.Id
                    Details = $detail
                    PhishingResistant = $MethodMap[$key].Strong
                    WeakMethod = $MethodMap[$key].Weak
                    RiskLevel = $MethodMap[$key].RiskLevel
                    Description = $MethodMap[$key].Description
                    LastUsed = $m.LastUsedDateTime
                    Created = $m.CreatedDateTime
                }
            }
        }
        catch {
            if ($_.Exception.Message -match "NotFound" -or $_.Exception.Message -match "No authentication methods") {
                Write-Log "No $($MethodMap[$key].Type) methods found for user $UPN" -Level Verbose -TenantId $TenantId
            }
            else {
                Write-Log "Error retrieving $($MethodMap[$key].Type) methods for user $UPN`: $($_.Exception.Message)" -Level Warning -TenantId $TenantId
            }
        }
    }
    
    return $methods
}

# Enhanced tenant audit with batch processing and progress tracking
function Audit-Tenant {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId
    )
    
    Write-Log "Starting audit for tenant $TenantId" -Level Information -TenantId $TenantId
    
    try {
        # Connect to tenant
        Connect-Tenant -TenantId $TenantId
        
        # Get organization details
        $org = Invoke-WithRetry -ScriptBlock {
            Get-MgOrganization | Select-Object -First 1 DisplayName, Id
        } -OperationName "Get organization details for tenant $TenantId"
        
        # Get all member users
        Write-Log "Retrieving user list for tenant $TenantId" -Level Information -TenantId $TenantId
        $users = Invoke-WithRetry -ScriptBlock {
            Get-MgUser -All -Filter "userType eq 'Member'" -Select Id, UserPrincipalName, DisplayName, AccountEnabled, CreatedDateTime, LastSignInDateTime
        } -OperationName "Get users for tenant $TenantId"
        
        Write-Log "Found $($users.Count) member users in tenant $TenantId" -Level Information -TenantId $TenantId
        
        # Process users in batches for better performance
        $results = @()
        $totalBatches = [Math]::Ceiling($users.Count / $BatchSize)
        
        for ($batchIndex = 0; $batchIndex -lt $totalBatches; $batchIndex++) {
            $startIndex = $batchIndex * $BatchSize
            $endIndex = [Math]::Min(($batchIndex + 1) * $BatchSize - 1, $users.Count - 1)
            $batchUsers = $users[$startIndex..$endIndex]
            
            Write-Log "Processing batch $($batchIndex + 1) of $totalBatches (users $($startIndex + 1) to $($endIndex + 1))" -Level Information -TenantId $TenantId
            
            $batchResults = foreach ($u in $batchUsers) {
                try {
                    $methods = Get-UserMethods -UserId $u.Id -UPN $u.UserPrincipalName -TenantId $TenantId
                    $strongCount = ($methods | Where-Object PhishingResistant).Count
                    $weakCount = ($methods | Where-Object WeakMethod).Count
                    
                    # Enhanced recommendation logic
                    $recommendation = switch ($true) {
                        ($weakCount -gt 0 -and $strongCount -gt 0) { 'Remove weak methods' }
                        ($weakCount -gt 0 -and $strongCount -eq 0) { 'Add strong method first' }
                        ($weakCount -eq 0 -and $strongCount -eq 0) { 'Add strong method' }
                        ($weakCount -eq 0 -and $strongCount -gt 0) { 'OK' }
                        default { 'Review required' }
                    }
                    
                    [PSCustomObject]@{
                        TenantId = $TenantId
                        TenantName = $org.DisplayName
                        UserPrincipalName = $u.UserPrincipalName
                        DisplayName = $u.DisplayName
                        Enabled = $u.AccountEnabled
                        CreatedDate = $u.CreatedDateTime
                        LastSignIn = $u.LastSignInDateTime
                        TotalMethods = $methods.Count
                        StrongMethodsCount = $strongCount
                        WeakMethodsCount = $weakCount
                        MethodDetails = ($methods | ForEach-Object { "$($_.MethodType):$($_.Details)" }) -join '; '
                        RiskLevel = if ($weakCount -gt 0) { 'High' } elseif ($strongCount -eq 0) { 'Medium' } else { 'Low' }
                        RecommendedAction = $recommendation
                        AuditTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
                catch {
                    Write-Log "Error processing user $($u.UserPrincipalName)`: $($_.Exception.Message)" -Level Warning -TenantId $TenantId
                    
                    # Return error record
                    [PSCustomObject]@{
                        TenantId = $TenantId
                        TenantName = $org.DisplayName
                        UserPrincipalName = $u.UserPrincipalName
                        DisplayName = $u.DisplayName
                        Enabled = $u.AccountEnabled
                        CreatedDate = $u.CreatedDateTime
                        LastSignIn = $u.LastSignInDateTime
                        TotalMethods = 0
                        StrongMethodsCount = 0
                        WeakMethodsCount = 0
                        MethodDetails = "ERROR: $($_.Exception.Message)"
                        RiskLevel = 'Unknown'
                        RecommendedAction = 'Review error'
                        AuditTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                }
            }
            
            $results += $batchResults
            
            # Progress update
            $progressPercent = (($batchIndex + 1) / $totalBatches) * 100
            Write-Progress -Activity "Auditing tenant $TenantId" -Status "Processed $($results.Count) of $($users.Count) users" -PercentComplete $progressPercent
        }
        
        Write-Progress -Activity "Auditing tenant $TenantId" -Completed
        
        # Export detailed CSV with enhanced naming
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvFileName = "AuthAudit_${TenantId}_${timestamp}.csv"
        $csvPath = Join-Path $ExportPath $csvFileName
        
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "Exported detailed audit report: $csvPath" -Level Information -TenantId $TenantId
        
        # Generate summary statistics
        $summary = [PSCustomObject]@{
            TenantId = $TenantId
            TenantName = $org.DisplayName
            TotalUsers = $users.Count
            UsersWithStrong = ($results | Where-Object StrongMethodsCount -gt 0).Count
            UsersWithWeak = ($results | Where-Object WeakMethodsCount -gt 0).Count
            UsersWithBoth = ($results | Where-Object { $_.StrongMethodsCount -gt 0 -and $_.WeakMethodsCount -gt 0 }).Count
            UsersWithNoMethods = ($results | Where-Object TotalMethods -eq 0).Count
            HighRiskUsers = ($results | Where-Object RiskLevel -eq 'High').Count
            MediumRiskUsers = ($results | Where-Object RiskLevel -eq 'Medium').Count
            LowRiskUsers = ($results | Where-Object RiskLevel -eq 'Low').Count
            AuditTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        return @{
            Summary = $summary
            Results = $results
            CsvPath = $csvPath
        }
    }
    catch {
        Write-Log "Critical error during tenant audit for $TenantId`: $($_.Exception.Message)" -Level Error -TenantId $TenantId
        throw
    }
}

# Enhanced export directory preparation
function Initialize-ExportDirectory {
    param([string]$Path)
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
            Write-Log "Created export directory: $Path" -Level Information
        }
        
        # Test write permissions
        $testFile = Join-Path $Path "write_test.tmp"
        "test" | Out-File -FilePath $testFile -ErrorAction Stop
        Remove-Item $testFile -ErrorAction SilentlyContinue
        
        Write-Log "Export directory ready: $Path" -Level Information
        return $true
    }
    catch {
        Write-Log "Failed to prepare export directory $Path`: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Main execution function
function Start-AzureAuthAudit {
    try {
        Write-Log "Starting Azure AD Authentication Methods Audit" -Level Information
        Write-Log "Script version: 2.0" -Level Information
        Write-Log "Parameters: Tenants=$($TenantID.Count), ExportPath=$ExportPath, BatchSize=$BatchSize, LogLevel=$LogLevel" -Level Information
        
        # Initialize modules
        Initialize-RequiredModules
        
        # Prepare export directory
        Initialize-ExportDirectory -Path $ExportPath
        
        # Start transcript logging if supported
        $transcriptPath = Join-Path $ExportPath "Audit_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        try {
            Start-Transcript -Path $transcriptPath -Append
            Write-Log "Transcript logging started: $transcriptPath" -Level Information
        }
        catch {
            Write-Log "Transcript logging not available, continuing without it" -Level Warning
        }
        
        # Run audits for each tenant
        $auditResults = @()
        $startTime = Get-Date
        
        foreach ($tid in $TenantID) {
            try {
                $tenantStartTime = Get-Date
                $result = Audit-Tenant -TenantId $tid
                $tenantEndTime = Get-Date
                $duration = $tenantEndTime - $tenantStartTime
                
                Write-Log "Tenant $tid audit completed in $($duration.TotalSeconds.ToString('F1')) seconds" -Level Information -TenantId $tid
                
                $auditResults += $result
            }
            catch {
                Write-Log "Failed to audit tenant $tid`: $($_.Exception.Message)" -Level Error -TenantId $tid
                
                # Add error summary to results
                $auditResults += @{
                    Summary = [PSCustomObject]@{
                        TenantId = $tid
                        TenantName = "ERROR - Connection Failed"
                        TotalUsers = 0
                        UsersWithStrong = 0
                        UsersWithWeak = 0
                        UsersWithBoth = 0
                        UsersWithNoMethods = 0
                        HighRiskUsers = 0
                        MediumRiskUsers = 0
                        LowRiskUsers = 0
                        AuditTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Error = $_.Exception.Message
                    }
                    Results = @()
                    CsvPath = $null
                }
            }
        }
        
        # Export consolidated summary
        $summaryTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $summaryCsvPath = Join-Path $ExportPath "AuthAudit_Summary_${summaryTimestamp}.csv"
        
        $summaries = $auditResults | ForEach-Object { $_.Summary }
        $summaries | Export-Csv -Path $summaryCsvPath -NoTypeInformation -Encoding UTF8
        
        # Generate executive summary
        $totalEndTime = Get-Date
        $totalDuration = $totalEndTime - $startTime
        
        Write-Log "`n=== AUDIT COMPLETED ===" -Level Information
        Write-Log "Total execution time: $($totalDuration.TotalMinutes.ToString('F1')) minutes" -Level Information
        Write-Log "Tenants processed: $($auditResults.Count)" -Level Information
        Write-Log "Total users audited: $(($summaries | Measure-Object TotalUsers -Sum).Sum)" -Level Information
        Write-Log "High-risk users: $(($summaries | Measure-Object HighRiskUsers -Sum).Sum)" -Level Information
        Write-Log "Consolidated summary exported: $summaryCsvPath" -Level Information
        
        # Display summary table
        $summaries | Format-Table -AutoSize
        
        # Stop transcript
        try {
            Stop-Transcript
            Write-Log "Transcript logging stopped" -Level Information
        }
        catch {
            Write-Log "Transcript logging already stopped" -Level Warning
        }
        
        return $auditResults
    }
    catch {
        Write-Log "Critical error during audit execution: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Script execution
try {
    $results = Start-AzureAuthAudit
    Write-Log "Script completed successfully" -Level Information
}
catch {
    Write-Log "Script failed with error: $($_.Exception.Message)" -Level Error
    exit 1
}