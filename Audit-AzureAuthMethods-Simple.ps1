<#
.SYNOPSIS
    Multi-Tenant Azure AD Authentication Methods Audit (Read-Only) - Simplified Version

.DESCRIPTION
    Connects to one or more Azure tenants via Microsoft Graph,
    inventories every member user's registered auth methods (weak and phishing-resistant),
    and exports detailed CSV reports and summary statistics.

.PARAMETER TenantID
    Array of Azure Tenant IDs to audit.

.PARAMETER ExportPath
    Directory to save CSV reports (default: current folder).

.EXAMPLE
    .\Audit-AzureAuthMethods-Simple.ps1 -TenantID "tenant1","tenant2" -ExportPath "C:\Reports"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = "Array of Azure Tenant IDs to audit")]
    [ValidateNotNullOrEmpty()]
    [string[]]$TenantID,
    
    [Parameter(HelpMessage = "Directory to save CSV reports")]
    [ValidateNotNullOrEmpty()]
    [string]$ExportPath = $PWD
)

# Script configuration
$ScriptConfig = @{
    RequiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
    MaxRetries = 3
    RetryDelaySeconds = 5
}

# Simple logging function
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Error", "Warning", "Information")]
        [string]$Level = "Information"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error"   { Write-Error $logMessage -ErrorAction Continue }
        "Warning" { Write-Warning $logMessage }
        "Information" { Write-Host $logMessage -ForegroundColor White }
    }
}

# Simple retry logic
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

# Module management
function Initialize-RequiredModules {
    Write-Log "Initializing required PowerShell modules..." -Level Information
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    Write-Log "PowerShell version: $psVersion" -Level Information
    
    # Check execution policy
    $executionPolicy = Get-ExecutionPolicy
    Write-Log "Execution policy: $executionPolicy" -Level Information
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    Write-Log "Running as Administrator: $isAdmin" -Level Information
    
    foreach ($module in $ScriptConfig.RequiredModules) {
        try {
            Write-Log "Checking module: $module" -Level Information
            
            # Check if module is already installed
            if (-not (Get-Module -ListAvailable $module)) {
                Write-Log "Module $module not installed. Attempting to install..." -Level Information
                
                # Try to install with CurrentUser scope first
                try {
                    Install-Module $module -Force -Scope CurrentUser -ErrorAction Stop
                    Write-Log "Successfully installed $module to CurrentUser scope" -Level Information
                }
                catch {
                    Write-Log "CurrentUser installation failed: $($_.Exception.Message)" -Level Warning
                    
                    if ($isAdmin) {
                        Write-Log "Trying AllUsers scope..." -Level Information
                        Install-Module $module -Force -Scope AllUsers -ErrorAction Stop
                        Write-Log "Successfully installed $module to AllUsers scope" -Level Information
                    }
                    else {
                        throw "Failed to install module $module. Try running as Administrator or manually install with: Install-Module $module -Force -Scope CurrentUser"
                    }
                }
            }
            else {
                Write-Log "Module $module is already installed" -Level Information
            }
            
            # Import module
            if (-not (Get-Module $module)) {
                Write-Log "Importing module: $module" -Level Information
                Import-Module $module -Force -ErrorAction Stop
                Write-Log "Successfully imported module: $module" -Level Information
            }
            else {
                Write-Log "Module $module is already imported" -Level Information
            }
        }
        catch {
            Write-Log "Failed to install/import module $module`: $($_.Exception.Message)" -Level Error
            
            # Provide troubleshooting information
            Write-Log "Troubleshooting steps:" -Level Information
            Write-Log "1. Check internet connection" -Level Information
            Write-Log "2. Verify PowerShell execution policy: Get-ExecutionPolicy" -Level Information
            Write-Log "3. Try: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -Level Information
            Write-Log "4. Check available modules: Get-PSRepository" -Level Information
            Write-Log "5. Try: Install-Module $module -Force -Scope CurrentUser" -Level Information
            
            throw "Module initialization failed for $module"
        }
    }
    
    Write-Log "All required modules initialized successfully" -Level Information
}

# Authentication method mapping
$MethodMap = @{
    Phone = @{ 
        Cmd = 'Get-MgUserAuthenticationPhoneMethod'
        Type = 'Phone/SMS'
        Weak = $true
        Strong = $false
    }
    Email = @{ 
        Cmd = 'Get-MgUserAuthenticationEmailMethod'
        Type = 'Email OTP'
        Weak = $true
        Strong = $false
    }
    Fido2 = @{ 
        Cmd = 'Get-MgUserAuthenticationFido2Method'
        Type = 'FIDO2'
        Weak = $false
        Strong = $true
    }
    Authenticator = @{ 
        Cmd = 'Get-MgUserAuthenticationMicrosoftAuthenticatorMethod'
        Type = 'Microsoft Authenticator'
        Weak = $false
        Strong = $true
    }
    Hello = @{ 
        Cmd = 'Get-MgUserAuthenticationWindowsHelloForBusinessMethod'
        Type = 'Windows Hello'
        Weak = $false
        Strong = $true
    }
    TAP = @{ 
        Cmd = 'Get-MgUserAuthenticationTemporaryAccessPassMethod'
        Type = 'Temporary Access Pass'
        Weak = $false
        Strong = $false
    }
    OATH = @{ 
        Cmd = 'Get-MgUserAuthenticationSoftwareOathMethod'
        Type = 'Software OATH'
        Weak = $false
        Strong = $false
    }
}

# Get user authentication methods
function Get-UserMethods {
    param(
        [Parameter(Mandatory)]
        [string]$UserId,
        
        [Parameter(Mandatory)]
        [string]$UPN
    )
    
    $methods = @()
    
    foreach ($key in $MethodMap.Keys) {
        try {
            $list = & $MethodMap[$key].Cmd -UserId $UserId -ErrorAction Stop
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
                }
            }
        }
        catch {
            # Silently continue if method not found
            if ($PSBoundParameters.ContainsKey('Verbose')) { 
                Write-Verbose "No $($MethodMap[$key].Type) methods found for user $UPN" 
            }
        }
    }
    
    return $methods
}

# Connect to tenant
function Connect-Tenant {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId
    )
    
    Write-Log "Connecting to tenant $TenantId..." -Level Information
    
    try {
        # Check if already connected to this tenant
        $context = Get-MgContext
        if ($context -and $context.TenantId -eq $TenantId) {
            Write-Log "Already connected to tenant $TenantId" -Level Information
            return $true
        }
        
        # Disconnect if connected to different tenant
        if ($context) {
            Write-Log "Disconnecting from current tenant to connect to $TenantId" -Level Information
            Disconnect-MgGraph
        }
        
        # Connect to target tenant
        Connect-MgGraph -TenantId $TenantId -Scopes @(
            'User.Read.All',
            'UserAuthenticationMethod.Read.All'
        ) -ErrorAction Stop
        
        Write-Log "Successfully connected to tenant $TenantId" -Level Information
        return $true
    }
    catch {
        Write-Log "Failed to connect to tenant $TenantId`: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Audit tenant
function Audit-Tenant {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId
    )
    
    Write-Log "Starting audit for tenant $TenantId" -Level Information
    
    try {
        # Connect to tenant
        Connect-Tenant -TenantId $TenantId
        
        # Get organization details
        $org = Get-MgOrganization | Select-Object -First 1 DisplayName
        
        # Get all member users
        Write-Log "Retrieving user list for tenant $TenantId" -Level Information
        $users = Get-MgUser -All -Filter "userType eq 'Member'" -Select Id, UserPrincipalName, DisplayName, AccountEnabled
        
        Write-Log "Found $($users.Count) member users in tenant $TenantId" -Level Information
        
        # Process users
        $results = @()
        $processedCount = 0
        
        foreach ($u in $users) {
            try {
                $methods = Get-UserMethods -UserId $u.Id -UPN $u.UserPrincipalName
                $strongCount = ($methods | Where-Object PhishingResistant).Count
                $weakCount = ($methods | Where-Object WeakMethod).Count
                
                # Recommendation logic
                $recommendation = switch ($true) {
                    ($weakCount -gt 0 -and $strongCount -gt 0) { 'Remove weak methods' }
                    ($weakCount -gt 0 -and $strongCount -eq 0) { 'Add strong method first' }
                    ($weakCount -eq 0 -and $strongCount -eq 0) { 'Add strong method' }
                    ($weakCount -eq 0 -and $strongCount -gt 0) { 'OK' }
                    default { 'Review required' }
                }
                
                $results += [PSCustomObject]@{
                    TenantId = $TenantId
                    TenantName = $org.DisplayName
                    UserPrincipalName = $u.UserPrincipalName
                    DisplayName = $u.DisplayName
                    Enabled = $u.AccountEnabled
                    TotalMethods = $methods.Count
                    StrongMethodsCount = $strongCount
                    WeakMethodsCount = $weakCount
                    MethodDetails = ($methods | ForEach-Object { "$($_.MethodType):$($_.Details)" }) -join '; '
                    RecommendedAction = $recommendation
                }
                
                $processedCount++
                if ($processedCount % 10 -eq 0) {
                    Write-Log "Processed $processedCount of $($users.Count) users" -Level Information
                }
            }
            catch {
                Write-Log "Error processing user $($u.UserPrincipalName)`: $($_.Exception.Message)" -Level Warning
            }
        }
        
        # Export CSV
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $csvFileName = "AuthAudit_${TenantId}_${timestamp}.csv"
        $csvPath = Join-Path $ExportPath $csvFileName
        
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "Exported audit report: $csvPath" -Level Information
        
        # Generate summary
        $summary = [PSCustomObject]@{
            TenantId = $TenantId
            TenantName = $org.DisplayName
            TotalUsers = $users.Count
            UsersWithStrong = ($results | Where-Object StrongMethodsCount -gt 0).Count
            UsersWithWeak = ($results | Where-Object WeakMethodsCount -gt 0).Count
            UsersWithBoth = ($results | Where-Object { $_.StrongMethodsCount -gt 0 -and $_.WeakMethodsCount -gt 0 }).Count
        }
        
        return $summary
    }
    catch {
        Write-Log "Critical error during tenant audit for $TenantId`: $($_.Exception.Message)" -Level Error
        throw
    }
}

# Main execution
try {
    Write-Log "Starting Azure AD Authentication Methods Audit (Simplified)" -Level Information
    
    # Initialize modules
    Initialize-RequiredModules
    
    # Prepare export directory
    if (-not (Test-Path $ExportPath)) { 
        New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null 
        Write-Log "Created export directory: $ExportPath" -Level Information
    }
    
    # Run audits
    $summaries = @()
    foreach ($tid in $TenantID) {
        try {
            $summary = Audit-Tenant -TenantId $tid
            $summaries += $summary
        }
        catch {
            Write-Log "Failed to audit tenant $tid`: $($_.Exception.Message)" -Level Error
        }
    }
    
    # Export consolidated summary
    if ($summaries.Count -gt 0) {
        $summaryCsv = Join-Path $ExportPath "AuthAudit_Summary_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
        $summaries | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8
        Write-Log "Consolidated summary exported: $summaryCsv" -Level Information
        
        # Display summary
        $summaries | Format-Table -AutoSize
    }
    
    Write-Log "Script completed successfully" -Level Information
}
catch {
    Write-Log "Script failed with error: $($_.Exception.Message)" -Level Error
    exit 1
}