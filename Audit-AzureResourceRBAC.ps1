#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive audit script for Azure Resource RBAC assignments with PIM detection
    
.DESCRIPTION
    This script audits all Azure resource role assignments across different scopes, including:
    - Management Group level assignments
    - Subscription level assignments  
    - Resource Group level assignments
    - Resource level assignments
    - PIM (Privileged Identity Management) eligible and active assignments
    - Direct and group-based assignments for both human and non-human identities
    
    The script is compatible with PowerShell 5.1 and uses Microsoft Graph API modules.
    
.PARAMETER TenantIds
    Array of Azure Tenant IDs to audit. If not specified, uses the current connected tenant.
    Supports multi-tenant auditing across multiple Azure AD tenants.
    
.PARAMETER DryRun
    Switch to run in dry-run mode. In dry-run mode, the script will simulate the audit process
    without making any actual API calls that could modify data. Useful for testing and validation.
    
.PARAMETER SubscriptionIds
    Array of specific subscription IDs to audit. If not specified, audits all accessible subscriptions.
    
.PARAMETER ExportPath
    Directory path where the CSV reports will be saved. Default is current directory.
    
.PARAMETER IncludeGroupMembers
    Switch to include individual group members when roles are assigned to groups.
    
.PARAMETER IncludeResourceLevel
    Switch to include resource-level role assignments (can be time-consuming for large environments).
    
.PARAMETER LogLevel
    Logging verbosity level. Valid values: Error, Warning, Information, Verbose, Debug
    Default: Information
    
.PARAMETER BatchSize
    Number of assignments to process per batch for better performance.
    Default: 50, Range: 1-200
    
.EXAMPLE
    .\Audit-AzureResourceRBAC.ps1 -TenantIds @("12345678-1234-1234-1234-123456789012")
    
.EXAMPLE
    .\Audit-AzureResourceRBAC.ps1 -TenantIds @("12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321") -SubscriptionIds @("sub1", "sub2") -IncludeGroupMembers -IncludeResourceLevel -DryRun
    
.NOTES
    Author: Azure Audit Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
    Required Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.Governance, Az.Resources, Az.Accounts
    Required Permissions: Directory.Read.All, RoleManagement.Read.All, PrivilegedAccess.Read.AzureResources, Reader access on Azure subscriptions
    
    MINIMUM GRAPH API PERMISSIONS:
    - Directory.Read.All (Application/Delegated): Read user, group, service principal information
    - RoleManagement.Read.All (Application/Delegated): Read Azure role definitions
    - PrivilegedAccess.Read.AzureResources (Application/Delegated): Read PIM data for Azure resources
    
    MINIMUM AZURE RBAC PERMISSIONS:
    - Reader (at Root Management Group): Comprehensive access to all Azure resources
    - Reader (per Subscription): Minimum access for subscription-level auditing
    - Security Reader: Enhanced security insights across Azure resources
    
    MINIMUM USER ROLES:
    - Global Reader + Reader on Azure subscriptions (recommended)
    - Security Reader (minimum): Basic visibility with some limitations
    - Privileged Role Administrator: Required for complete Azure PIM access
    
    MULTI-TENANT REQUIREMENTS:
    - Application must be registered as multi-tenant
    - Admin consent required in each target tenant
    - User must have appropriate Azure roles in each tenant
    - Cross-tenant access requires proper Azure lighthouse or guest permissions
    
    Multi-Tenant Support: This script supports auditing multiple tenants in a single execution.
    Dry-Run Mode: Use -DryRun to simulate the audit process without making actual API calls.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$TenantIds,
    
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeGroupMembers,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeResourceLevel,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Error', 'Warning', 'Information', 'Verbose', 'Debug')]
    [string]$LogLevel = 'Information',
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 200)]
    [int]$BatchSize = 50
)

# Script configuration
$ScriptConfig = @{
    Name = 'Audit-AzureResourceRBAC'
    Version = '1.0'
    RequiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Identity.Governance',
        'Az.Accounts',
        'Az.Resources'
    )
    GraphRequiredScopes = @(
        'Directory.Read.All',
        'RoleManagement.Read.All',
        'PrivilegedAccess.Read.AzureResources'
    )
}

# Global variables for logging and progress tracking
$Global:LogLevel = $LogLevel
$Global:LogEntries = @()
$Global:ProcessedCount = 0
$Global:ErrorCount = 0

#region Logging Functions
function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Error', 'Warning', 'Information', 'Verbose', 'Debug')]
        [string]$Level = 'Information',
        
        [Parameter(Mandatory = $false)]
        [string]$Component = 'Main'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Component = $Component
        Message = $Message
    }
    
    $Global:LogEntries += [PSCustomObject]$logEntry
    
    # Console output based on log level
    $levelValue = switch ($Level) {
        'Error' { 0 }
        'Warning' { 1 }
        'Information' { 2 }
        'Verbose' { 3 }
        'Debug' { 4 }
        default { 2 }
    }
    
    $currentLevelValue = switch ($Global:LogLevel) {
        'Error' { 0 }
        'Warning' { 1 }
        'Information' { 2 }
        'Verbose' { 3 }
        'Debug' { 4 }
        default { 2 }
    }
    
    if ($levelValue -le $currentLevelValue) {
        $colorMap = @{
            'Error' = 'Red'
            'Warning' = 'Yellow'
            'Information' = 'White'
            'Verbose' = 'Cyan'
            'Debug' = 'Gray'
        }
        
        Write-Host "[$timestamp] [$Level] [$Component] $Message" -ForegroundColor $colorMap[$Level]
    }
    
    # Increment error counter
    if ($Level -eq 'Error') {
        $Global:ErrorCount++
    }
}

function Export-LogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )
    
    try {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $logFileName = "AzureResourceRBAC_Log_{0}_{1}.csv" -f $TenantId, $timestamp
        $logFilePath = Join-Path -Path $ExportPath -ChildPath $logFileName
        
        $Global:LogEntries | Export-Csv -Path $logFilePath -NoTypeInformation -Encoding UTF8
        Write-LogMessage -Message "Log file exported to: $logFilePath" -Level 'Information' -Component 'Export'
    }
    catch {
        Write-LogMessage -Message "Failed to export log file: $($_.Exception.Message)" -Level 'Error' -Component 'Export'
    }
}
#endregion

#region Module Management
function Test-RequiredModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredModules
    )
    
    Write-LogMessage -Message "Checking required PowerShell modules..." -Level 'Information' -Component 'ModuleCheck'
    
    $missingModules = @()
    
    foreach ($module in $RequiredModules) {
        try {
            $installedModule = Get-Module -Name $module -ListAvailable -ErrorAction SilentlyContinue
            if (-not $installedModule) {
                $missingModules += $module
                Write-LogMessage -Message "Module not found: $module" -Level 'Warning' -Component 'ModuleCheck'
            }
            else {
                Write-LogMessage -Message "Module found: $module (Version: $($installedModule[0].Version))" -Level 'Verbose' -Component 'ModuleCheck'
            }
        }
        catch {
            Write-LogMessage -Message "Error checking module $module`: $($_.Exception.Message)" -Level 'Error' -Component 'ModuleCheck'
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-LogMessage -Message "Missing modules will be installed: $($missingModules -join ', ')" -Level 'Warning' -Component 'ModuleCheck'
        return $false
    }
    
    Write-LogMessage -Message "All required modules are available" -Level 'Information' -Component 'ModuleCheck'
    return $true
}

function Install-RequiredModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredModules
    )
    
    Write-LogMessage -Message "Installing required PowerShell modules..." -Level 'Information' -Component 'ModuleInstall'
    
    # Determine installation scope
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $scope = if ($isAdmin) { 'AllUsers' } else { 'CurrentUser' }
    
    Write-LogMessage -Message "Installation scope: $scope" -Level 'Information' -Component 'ModuleInstall'
    
    foreach ($module in $RequiredModules) {
        try {
            Write-LogMessage -Message "Installing module: $module" -Level 'Information' -Component 'ModuleInstall'
            Install-Module -Name $module -Scope $scope -Force -AllowClobber -ErrorAction Stop
            Write-LogMessage -Message "Successfully installed module: $module" -Level 'Information' -Component 'ModuleInstall'
        }
        catch {
            Write-LogMessage -Message "Failed to install module $module`: $($_.Exception.Message)" -Level 'Error' -Component 'ModuleInstall'
            throw "Module installation failed for: $module"
        }
    }
}

function Import-RequiredModules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredModules
    )
    
    Write-LogMessage -Message "Importing required PowerShell modules..." -Level 'Information' -Component 'ModuleImport'
    
    foreach ($module in $RequiredModules) {
        try {
            Import-Module -Name $module -Force -ErrorAction Stop
            Write-LogMessage -Message "Successfully imported module: $module" -Level 'Verbose' -Component 'ModuleImport'
        }
        catch {
            Write-LogMessage -Message "Failed to import module $module`: $($_.Exception.Message)" -Level 'Error' -Component 'ModuleImport'
            throw "Module import failed for: $module"
        }
    }
}
#endregion

#region Azure Connections
function Connect-ToAzure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-LogMessage -Message "DRY RUN: Would connect to Azure for tenant: $TenantId" -Level 'Information' -Component 'AzureConnection'
        return $TenantId
    }
    
    try {
        Write-LogMessage -Message "Connecting to Azure for tenant: $TenantId" -Level 'Information' -Component 'AzureConnection'
        
        # Always disconnect first to ensure clean connection for each tenant
        try {
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            # Ignore disconnect errors
        }
        
        # Connect to Azure
        $connectParams = @{
            TenantId = $TenantId
            ErrorAction = 'Stop'
        }
        
        $connection = Connect-AzAccount @connectParams
        $newContext = Get-AzContext
        
        Write-LogMessage -Message "Successfully connected to Azure. Tenant: ${newContext}.Tenant.Id" -Level 'Information' -Component 'AzureConnection'
        return $newContext.Tenant.Id
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Azure for tenant ${TenantId}: ${_}.Exception.Message" -Level 'Error' -Component 'AzureConnection'
        throw
    }
}

function Connect-ToMicrosoftGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredScopes,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-LogMessage -Message "DRY RUN: Would connect to Microsoft Graph for tenant: $TenantId" -Level 'Information' -Component 'GraphConnection'
        return $TenantId
    }
    
    try {
        Write-LogMessage -Message "Connecting to Microsoft Graph for tenant: $TenantId" -Level 'Information' -Component 'GraphConnection'
        
        # Always disconnect first to ensure clean connection for each tenant
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            # Ignore disconnect errors
        }
        
        # Connect with required scopes
        $connectParams = @{
            TenantId = $TenantId
            Scopes = $RequiredScopes
            ErrorAction = 'Stop'
        }
        
        $connection = Connect-MgGraph @connectParams
        $newContext = Get-MgContext
        
        Write-LogMessage -Message "Successfully connected to Microsoft Graph. Tenant: ${newContext}.TenantId" -Level 'Information' -Component 'GraphConnection'
        return $newContext.TenantId
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Microsoft Graph for tenant ${TenantId}: ${_}.Exception.Message" -Level 'Error' -Component 'GraphConnection'
        throw
    }
}
#endregion

#region PIM Detection
function Test-AzurePIMEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-LogMessage -Message "DRY RUN: Would check if Azure PIM is enabled in the tenant" -Level 'Information' -Component 'PIMDetection'
        return $true  # Assume Azure PIM is enabled in dry-run mode for testing
    }
    
    try {
        Write-LogMessage -Message "Checking if Azure PIM is enabled in the tenant..." -Level 'Information' -Component 'PIMDetection'
        
        # Try to access Azure PIM resources - if successful, PIM is enabled
        $pimResources = Get-MgIdentityGovernancePrivilegedAccessResource -PrivilegedAccessId 'azureResources' -Top 1 -ErrorAction SilentlyContinue
        
        if ($pimResources) {
            Write-LogMessage -Message "Azure PIM is enabled in this tenant" -Level 'Information' -Component 'PIMDetection'
            return $true
        }
        else {
            Write-LogMessage -Message "Azure PIM is not enabled in this tenant" -Level 'Information' -Component 'PIMDetection'
            return $false
        }
    }
    catch {
        Write-LogMessage -Message "Unable to determine Azure PIM status (assuming not enabled): ${_}.Exception.Message" -Level 'Warning' -Component 'PIMDetection'
        return $false
    }
}
#endregion

#region Scope Discovery
function Get-ManagementGroups {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Retrieving management groups..." -Level 'Information' -Component 'ScopeDiscovery'
        
        $managementGroups = @()
        $mgGroups = Get-AzManagementGroup -ErrorAction Stop
        
        foreach ($mg in $mgGroups) {
            $managementGroups += [PSCustomObject]@{
                Id = $mg.Id
                Name = $mg.Name
                DisplayName = $mg.DisplayName
                ParentId = $mg.ParentId
                Type = 'ManagementGroup'
            }
        }
        
        Write-LogMessage -Message "Retrieved $($managementGroups.Count) management groups" -Level 'Information' -Component 'ScopeDiscovery'
        return $managementGroups
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve management groups: $($_.Exception.Message)" -Level 'Warning' -Component 'ScopeDiscovery'
        return @()
    }
}

function Get-TargetSubscriptions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$SubscriptionIds
    )
    
    try {
        Write-LogMessage -Message "Retrieving target subscriptions..." -Level 'Information' -Component 'ScopeDiscovery'
        
        if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
            $subscriptions = @()
            foreach ($subId in $SubscriptionIds) {
                try {
                    $subscription = Get-AzSubscription -SubscriptionId $subId -ErrorAction Stop
                    $subscriptions += $subscription
                }
                catch {
                    Write-LogMessage -Message "Failed to retrieve subscription $subId`: $($_.Exception.Message)" -Level 'Warning' -Component 'ScopeDiscovery'
                }
            }
        }
        else {
            $subscriptions = Get-AzSubscription -ErrorAction Stop
        }
        
        Write-LogMessage -Message "Retrieved $($subscriptions.Count) target subscriptions" -Level 'Information' -Component 'ScopeDiscovery'
        return $subscriptions
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve subscriptions: $($_.Exception.Message)" -Level 'Error' -Component 'ScopeDiscovery'
        throw
    }
}

function Get-ResourceGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    
    try {
        Write-LogMessage -Message "Retrieving resource groups for subscription: $SubscriptionId" -Level 'Verbose' -Component 'ScopeDiscovery'
        
        # Set subscription context
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        
        $resourceGroups = Get-AzResourceGroup -ErrorAction Stop
        
        Write-LogMessage -Message "Retrieved $($resourceGroups.Count) resource groups from subscription $SubscriptionId" -Level 'Verbose' -Component 'ScopeDiscovery'
        return $resourceGroups
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve resource groups for subscription $SubscriptionId`: $($_.Exception.Message)" -Level 'Warning' -Component 'ScopeDiscovery'
        return @()
    }
}

function Get-Resources {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    
    if (-not $IncludeResourceLevel) {
        Write-LogMessage -Message "Resource-level assignments skipped (IncludeResourceLevel not specified)" -Level 'Information' -Component 'ScopeDiscovery'
        return @()
    }
    
    try {
        Write-LogMessage -Message "Retrieving resources for subscription: $SubscriptionId" -Level 'Verbose' -Component 'ScopeDiscovery'
        
        # Set subscription context
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        
        $resources = Get-AzResource -ErrorAction Stop
        
        Write-LogMessage -Message "Retrieved $($resources.Count) resources from subscription $SubscriptionId" -Level 'Verbose' -Component 'ScopeDiscovery'
        return $resources
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve resources for subscription $SubscriptionId`: $($_.Exception.Message)" -Level 'Warning' -Component 'ScopeDiscovery'
        return @()
    }
}
#endregion

#region Role Assignment Retrieval
function Get-AzureRoleDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    
    try {
        Write-LogMessage -Message "Retrieving Azure role definitions for subscription: $SubscriptionId" -Level 'Verbose' -Component 'RoleRetrieval'
        
        # Set subscription context
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        
        $roleDefinitions = @{}
        $roles = Get-AzRoleDefinition -ErrorAction Stop
        
        foreach ($role in $roles) {
            $roleDefinitions[$role.Id] = @{
                Id = $role.Id
                Name = $role.Name
                Description = $role.Description
                Type = $role.RoleType
                IsCustom = $role.IsCustom
                Actions = $role.Actions
                NotActions = $role.NotActions
            }
        }
        
        Write-LogMessage -Message "Retrieved $($roleDefinitions.Count) role definitions from subscription $SubscriptionId" -Level 'Verbose' -Component 'RoleRetrieval'
        return $roleDefinitions
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve role definitions for subscription $SubscriptionId`: $($_.Exception.Message)" -Level 'Warning' -Component 'RoleRetrieval'
        return @{}
    }
}

function Get-RoleAssignmentsForScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scope,
        
        [Parameter(Mandatory = $true)]
        [string]$ScopeName,
        
        [Parameter(Mandatory = $true)]
        [string]$ScopeType,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$RoleDefinitions,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    
    try {
        Write-LogMessage -Message "Retrieving role assignments for $ScopeType`: $ScopeName" -Level 'Verbose' -Component 'RoleRetrieval'
        
        $assignments = @()
        $roleAssignments = Get-AzRoleAssignment -Scope $Scope -ErrorAction Stop
        
        foreach ($assignment in $roleAssignments) {
            $roleAssignmentObj = [PSCustomObject]@{
                AssignmentId = $assignment.RoleAssignmentId
                PrincipalId = $assignment.ObjectId
                PrincipalDisplayName = $assignment.DisplayName
                PrincipalType = $assignment.ObjectType
                PrincipalEmail = $assignment.SignInName
                RoleId = $assignment.RoleDefinitionId
                RoleName = $assignment.RoleDefinitionName
                RoleDescription = ''
                AssignmentType = 'Direct'
                AssignmentMethod = 'Permanent'
                Scope = $ScopeType
                ScopeId = $Scope
                ScopeName = $ScopeName
                SubscriptionId = $SubscriptionId
                PIMStatus = 'Not PIM'
                ActivationStatus = 'Active'
                StartDateTime = ''
                EndDateTime = ''
                AssignedBy = ''
                AssignedDate = ''
                IsGroupAssignment = ($assignment.ObjectType -eq 'Group')
                GroupId = if ($assignment.ObjectType -eq 'Group') { $assignment.ObjectId } else { '' }
                GroupName = if ($assignment.ObjectType -eq 'Group') { $assignment.DisplayName } else { '' }
                Condition = $assignment.Condition
                ConditionVersion = $assignment.ConditionVersion
            }
            
            # Enrich role description
            if ($RoleDefinitions.ContainsKey($assignment.RoleDefinitionId)) {
                $roleAssignmentObj.RoleDescription = $RoleDefinitions[$assignment.RoleDefinitionId].Description
            }
            
            $assignments += $roleAssignmentObj
        }
        
        Write-LogMessage -Message "Retrieved $($assignments.Count) role assignments for $ScopeType`: $ScopeName" -Level 'Verbose' -Component 'RoleRetrieval'
        return $assignments
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve role assignments for $ScopeType $ScopeName`: $($_.Exception.Message)" -Level 'Warning' -Component 'RoleRetrieval'
        return @()
    }
}

function Get-PIMRoleAssignmentsForScope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ResourceId,
        
        [Parameter(Mandatory = $true)]
        [string]$ScopeName,
        
        [Parameter(Mandatory = $true)]
        [string]$ScopeType,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$RoleDefinitions,
        
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId
    )
    
    try {
        Write-LogMessage -Message "Retrieving PIM role assignments for $ScopeType`: $ScopeName" -Level 'Verbose' -Component 'PIMRetrieval'
        
        $assignments = @()
        
        # Get PIM eligible assignments for this resource
        try {
            $eligibleAssignments = Get-MgIdentityGovernancePrivilegedAccessRoleAssignment -PrivilegedAccessId 'azureResources' -Filter "resourceId eq '$ResourceId' and assignmentState eq 'Eligible'" -All -ErrorAction Stop
            
            foreach ($assignment in $eligibleAssignments) {
                $pimAssignment = [PSCustomObject]@{
                    AssignmentId = $assignment.Id
                    PrincipalId = $assignment.SubjectId
                    PrincipalDisplayName = ''
                    PrincipalType = ''
                    PrincipalEmail = ''
                    RoleId = $assignment.RoleDefinitionId
                    RoleName = ''
                    RoleDescription = ''
                    AssignmentType = 'PIM'
                    AssignmentMethod = 'Eligible'
                    Scope = $ScopeType
                    ScopeId = $ResourceId
                    ScopeName = $ScopeName
                    SubscriptionId = $SubscriptionId
                    PIMStatus = 'Eligible'
                    ActivationStatus = 'Eligible'
                    StartDateTime = $assignment.StartDateTime
                    EndDateTime = $assignment.EndDateTime
                    AssignedBy = ''
                    AssignedDate = $assignment.StartDateTime
                    IsGroupAssignment = $false
                    GroupId = ''
                    GroupName = ''
                    Condition = ''
                    ConditionVersion = ''
                }
                
                # Try to get role name from definitions
                if ($RoleDefinitions.ContainsKey($assignment.RoleDefinitionId)) {
                    $pimAssignment.RoleName = $RoleDefinitions[$assignment.RoleDefinitionId].Name
                    $pimAssignment.RoleDescription = $RoleDefinitions[$assignment.RoleDefinitionId].Description
                }
                
                $assignments += $pimAssignment
            }
        }
        catch {
            Write-LogMessage -Message "Error retrieving PIM eligible assignments for $ScopeType $ScopeName`: $($_.Exception.Message)" -Level 'Debug' -Component 'PIMRetrieval'
        }
        
        # Get PIM active assignments for this resource
        try {
            $activeAssignments = Get-MgIdentityGovernancePrivilegedAccessRoleAssignment -PrivilegedAccessId 'azureResources' -Filter "resourceId eq '$ResourceId' and assignmentState eq 'Active'" -All -ErrorAction Stop
            
            foreach ($assignment in $activeAssignments) {
                $pimAssignment = [PSCustomObject]@{
                    AssignmentId = $assignment.Id
                    PrincipalId = $assignment.SubjectId
                    PrincipalDisplayName = ''
                    PrincipalType = ''
                    PrincipalEmail = ''
                    RoleId = $assignment.RoleDefinitionId
                    RoleName = ''
                    RoleDescription = ''
                    AssignmentType = 'PIM'
                    AssignmentMethod = 'Active'
                    Scope = $ScopeType
                    ScopeId = $ResourceId
                    ScopeName = $ScopeName
                    SubscriptionId = $SubscriptionId
                    PIMStatus = 'Active'
                    ActivationStatus = 'Active'
                    StartDateTime = $assignment.StartDateTime
                    EndDateTime = $assignment.EndDateTime
                    AssignedBy = ''
                    AssignedDate = $assignment.StartDateTime
                    IsGroupAssignment = $false
                    GroupId = ''
                    GroupName = ''
                    Condition = ''
                    ConditionVersion = ''
                }
                
                # Try to get role name from definitions
                if ($RoleDefinitions.ContainsKey($assignment.RoleDefinitionId)) {
                    $pimAssignment.RoleName = $RoleDefinitions[$assignment.RoleDefinitionId].Name
                    $pimAssignment.RoleDescription = $RoleDefinitions[$assignment.RoleDefinitionId].Description
                }
                
                $assignments += $pimAssignment
            }
        }
        catch {
            Write-LogMessage -Message "Error retrieving PIM active assignments for $ScopeType $ScopeName`: $($_.Exception.Message)" -Level 'Debug' -Component 'PIMRetrieval'
        }
        
        Write-LogMessage -Message "Retrieved $($assignments.Count) PIM role assignments for $ScopeType`: $ScopeName" -Level 'Verbose' -Component 'PIMRetrieval'
        return $assignments
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve PIM role assignments for $ScopeType $ScopeName`: $($_.Exception.Message)" -Level 'Warning' -Component 'PIMRetrieval'
        return @()
    }
}
#endregion

#region Principal Information Enrichment
function Get-PrincipalInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Assignments
    )
    
    try {
        Write-LogMessage -Message "Enriching principal information for assignments..." -Level 'Information' -Component 'PrincipalEnrichment'
        
        $processedCount = 0
        $uniquePrincipalIds = $Assignments | Where-Object { $_.PrincipalId -and $_.PrincipalId -ne '' } | Select-Object -ExpandProperty PrincipalId -Unique
        
        foreach ($principalId in $uniquePrincipalIds) {
            try {
                # Skip if already has display name
                $principalAssignments = $Assignments | Where-Object { $_.PrincipalId -eq $principalId }
                if ($principalAssignments[0].PrincipalDisplayName -and $principalAssignments[0].PrincipalDisplayName -ne '') {
                    continue
                }
                
                # Try to get user information first
                $user = Get-MgUser -UserId $principalId -Property "Id,DisplayName,UserPrincipalName,UserType,AccountEnabled" -ErrorAction SilentlyContinue
                
                if ($user) {
                    # Update all assignments for this user
                    foreach ($assignment in $principalAssignments) {
                        $assignment.PrincipalDisplayName = $user.DisplayName
                        $assignment.PrincipalType = if ($user.UserType -eq 'Guest') { 'Guest User' } else { 'User' }
                        $assignment.PrincipalEmail = $user.UserPrincipalName
                    }
                }
                else {
                    # Try to get service principal information
                    $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $principalId -Property "Id,DisplayName,AppId,ServicePrincipalType" -ErrorAction SilentlyContinue
                    
                    if ($servicePrincipal) {
                        # Update all assignments for this service principal
                        foreach ($assignment in $principalAssignments) {
                            $assignment.PrincipalDisplayName = $servicePrincipal.DisplayName
                            $assignment.PrincipalType = 'Service Principal'
                            $assignment.PrincipalEmail = $servicePrincipal.AppId
                        }
                    }
                    else {
                        # Try to get group information
                        $group = Get-MgGroup -GroupId $principalId -Property "Id,DisplayName,GroupTypes,SecurityEnabled" -ErrorAction SilentlyContinue
                        
                        if ($group) {
                            # Update all assignments for this group
                            foreach ($assignment in $principalAssignments) {
                                $assignment.PrincipalDisplayName = $group.DisplayName
                                $assignment.PrincipalType = 'Group'
                                $assignment.PrincipalEmail = $group.Id
                                $assignment.IsGroupAssignment = $true
                                $assignment.GroupId = $group.Id
                                $assignment.GroupName = $group.DisplayName
                            }
                        }
                        else {
                            # Unknown principal type - might be deleted or external
                            foreach ($assignment in $principalAssignments) {
                                if (-not $assignment.PrincipalDisplayName) {
                                    $assignment.PrincipalDisplayName = "Unknown Principal"
                                }
                                if (-not $assignment.PrincipalType) {
                                    $assignment.PrincipalType = 'Unknown'
                                }
                                if (-not $assignment.PrincipalEmail) {
                                    $assignment.PrincipalEmail = $principalId
                                }
                            }
                            
                            Write-LogMessage -Message "Unknown principal type for ID: $principalId" -Level 'Debug' -Component 'PrincipalEnrichment'
                        }
                    }
                }
                
                $processedCount++
                if ($processedCount % $BatchSize -eq 0) {
                    Write-LogMessage -Message "Processed $processedCount principals..." -Level 'Verbose' -Component 'PrincipalEnrichment'
                }
            }
            catch {
                Write-LogMessage -Message "Error enriching principal $principalId`: $($_.Exception.Message)" -Level 'Debug' -Component 'PrincipalEnrichment'
                
                # Update assignments with error information
                $errorAssignments = $Assignments | Where-Object { $_.PrincipalId -eq $principalId }
                foreach ($assignment in $errorAssignments) {
                    if (-not $assignment.PrincipalDisplayName) {
                        $assignment.PrincipalDisplayName = "Error retrieving info"
                    }
                    if (-not $assignment.PrincipalType) {
                        $assignment.PrincipalType = 'Error'
                    }
                    if (-not $assignment.PrincipalEmail) {
                        $assignment.PrincipalEmail = $principalId
                    }
                }
            }
        }
        
        Write-LogMessage -Message "Completed principal enrichment for $processedCount principals" -Level 'Information' -Component 'PrincipalEnrichment'
        return $Assignments
    }
    catch {
        Write-LogMessage -Message "Failed to enrich principal information: $($_.Exception.Message)" -Level 'Error' -Component 'PrincipalEnrichment'
        throw
    }
}

function Get-GroupMemberRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$GroupAssignments
    )
    
    if (-not $IncludeGroupMembers) {
        Write-LogMessage -Message "Group member expansion skipped (IncludeGroupMembers not specified)" -Level 'Information' -Component 'GroupExpansion'
        return @()
    }
    
    try {
        Write-LogMessage -Message "Expanding group members for group-based role assignments..." -Level 'Information' -Component 'GroupExpansion'
        
        $memberAssignments = @()
        $processedGroups = 0
        
        foreach ($groupAssignment in $GroupAssignments) {
            try {
                $groupMembers = Get-MgGroupMember -GroupId $groupAssignment.GroupId -All -ErrorAction Stop
                
                foreach ($member in $groupMembers) {
                    # Create a copy of the group assignment for the member
                    $memberAssignment = $groupAssignment.PSObject.Copy()
                    $memberAssignment.AssignmentId = [guid]::NewGuid().ToString()
                    $memberAssignment.PrincipalId = $member.Id
                    $memberAssignment.PrincipalDisplayName = ''
                    $memberAssignment.PrincipalType = ''
                    $memberAssignment.PrincipalEmail = ''
                    $memberAssignment.AssignmentType = 'Group Member'
                    
                    $memberAssignments += $memberAssignment
                }
                
                $processedGroups++
                Write-LogMessage -Message "Processed group: $($groupAssignment.GroupName) ($($groupMembers.Count) members)" -Level 'Verbose' -Component 'GroupExpansion'
            }
            catch {
                Write-LogMessage -Message "Error expanding group $($groupAssignment.GroupName): $($_.Exception.Message)" -Level 'Warning' -Component 'GroupExpansion'
            }
        }
        
        # Enrich member information
        if ($memberAssignments.Count -gt 0) {
            $memberAssignments = Get-PrincipalInformation -Assignments $memberAssignments
        }
        
        Write-LogMessage -Message "Expanded $($memberAssignments.Count) member assignments from $processedGroups groups" -Level 'Information' -Component 'GroupExpansion'
        return $memberAssignments
    }
    catch {
        Write-LogMessage -Message "Failed to expand group members: $($_.Exception.Message)" -Level 'Error' -Component 'GroupExpansion'
        throw
    }
}
#endregion

#region Report Generation
function Export-ResourceRBACReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Assignments,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [bool]$IsPIMEnabled = $false,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $reportFileName = "AzureResourceRBAC_{0}_{1}.csv" -f $TenantId, $timestamp
        $reportFilePath = Join-Path -Path $ExportPath -ChildPath $reportFileName
        
        if ($DryRun) {
            Write-LogMessage -Message "DRY RUN: Would export Azure Resource RBAC report to: $reportFilePath" -Level 'Information' -Component 'Export'
            Write-LogMessage -Message "DRY RUN: Would export $($Assignments.Count) assignments" -Level 'Information' -Component 'Export'
            
            return @{
                ReportPath = "DRY_RUN_$reportFileName"
                SummaryPath = "DRY_RUN_AzureResourceRBAC_Summary_{0}_{1}.csv" -f $TenantId, $timestamp
                AssignmentCount = $Assignments.Count
            }
        }
        
        Write-LogMessage -Message "Exporting Azure Resource RBAC report to: $reportFilePath" -Level 'Information' -Component 'Export'
        
        # Ensure export directory exists
        if (-not (Test-Path -Path $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        }
        
        # Sort assignments for better readability
        $sortedAssignments = $Assignments | Sort-Object SubscriptionId, Scope, RoleName, PrincipalDisplayName
        
        # Export to CSV
        $sortedAssignments | Export-Csv -Path $reportFilePath -NoTypeInformation -Encoding UTF8
        
        # Generate summary report
        $summary = [PSCustomObject]@{
            TenantId = $TenantId
            ReportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            TotalAssignments = $Assignments.Count
            DirectAssignments = ($Assignments | Where-Object { $_.AssignmentType -eq 'Direct' }).Count
            PIMAssignments = ($Assignments | Where-Object { $_.AssignmentType -eq 'PIM' }).Count
            GroupAssignments = ($Assignments | Where-Object { $_.IsGroupAssignment -eq $true }).Count
            GroupMemberAssignments = ($Assignments | Where-Object { $_.AssignmentType -eq 'Group Member' }).Count
            ManagementGroupAssignments = ($Assignments | Where-Object { $_.Scope -eq 'ManagementGroup' }).Count
            SubscriptionAssignments = ($Assignments | Where-Object { $_.Scope -eq 'Subscription' }).Count
            ResourceGroupAssignments = ($Assignments | Where-Object { $_.Scope -eq 'ResourceGroup' }).Count
            ResourceAssignments = ($Assignments | Where-Object { $_.Scope -eq 'Resource' }).Count
            UniqueUsers = ($Assignments | Where-Object { $_.PrincipalType -in @('User', 'Guest User') } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            UniqueServicePrincipals = ($Assignments | Where-Object { $_.PrincipalType -eq 'Service Principal' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            UniqueGroups = ($Assignments | Where-Object { $_.PrincipalType -eq 'Group' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            UniqueRoles = ($Assignments | Select-Object -ExpandProperty RoleId -Unique).Count
            UniqueSubscriptions = ($Assignments | Where-Object { $_.SubscriptionId } | Select-Object -ExpandProperty SubscriptionId -Unique).Count
            PIMEnabled = $IsPIMEnabled
            ErrorCount = $Global:ErrorCount
        }
        
        $summaryFileName = "AzureResourceRBAC_Summary_{0}_{1}.csv" -f $TenantId, $timestamp
        $summaryFilePath = Join-Path -Path $ExportPath -ChildPath $summaryFileName
        $summary | Export-Csv -Path $summaryFilePath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage -Message "Report exported: $($Assignments.Count) assignments" -Level 'Information' -Component 'Export'
        Write-LogMessage -Message "Summary exported: $summaryFilePath" -Level 'Information' -Component 'Export'
        
        return @{
            ReportPath = $reportFilePath
            SummaryPath = $summaryFilePath
            AssignmentCount = $Assignments.Count
        }
    }
    catch {
        Write-LogMessage -Message "Failed to export report: $($_.Exception.Message)" -Level 'Error' -Component 'Export'
        throw
    }
}
#endregion

#region Multi-Tenant Execution
function Start-MultiTenantAzureResourceRBCAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$TenantIds,
        
        [Parameter(Mandatory = $false)]
        [string[]]$SubscriptionIds,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeGroupMembers,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeResourceLevel,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        Write-LogMessage -Message "Starting Multi-Tenant Azure Resource RBAC audit..." -Level 'Information' -Component 'MultiTenant'
        Write-LogMessage -Message "Script Version: $($ScriptConfig.Version)" -Level 'Information' -Component 'MultiTenant'
        
        if ($DryRun) {
            Write-LogMessage -Message "*** RUNNING IN DRY-RUN MODE - NO ACTUAL API CALLS WILL BE MADE ***" -Level 'Warning' -Component 'MultiTenant'
        }
        
        # Test and install required modules
        if (-not $DryRun) {
            if (-not (Test-RequiredModules -RequiredModules $($ScriptConfig.RequiredModules))) {
                Install-RequiredModules -RequiredModules $($ScriptConfig.RequiredModules)
            }
            
            # Import required modules
            Import-RequiredModules -RequiredModules $($ScriptConfig.RequiredModules)
        } else {
            Write-LogMessage -Message "DRY RUN: Would test and install required modules" -Level 'Information' -Component 'MultiTenant'
        }
        
        # If no tenant IDs specified, get current context
        if (-not $TenantIds -or $TenantIds.Count -eq 0) {
            if ($DryRun) {
                $TenantIds = @("dry-run-tenant-id")
                Write-LogMessage -Message "DRY RUN: Using mock tenant ID" -Level 'Information' -Component 'MultiTenant'
            } else {
                $context = Get-AzContext -ErrorAction SilentlyContinue
                if ($context) {
                    $TenantIds = @($context.Tenant.Id)
                    Write-LogMessage -Message "Using current connected tenant: $($context.Tenant.Id)" -Level 'Information' -Component 'MultiTenant'
                } else {
                    throw "No tenant IDs specified and no current Azure connection found"
                }
            }
        }
        
        Write-LogMessage -Message "Processing $($TenantIds.Count) tenant(s)" -Level 'Information' -Component 'MultiTenant'
        
        $allTenantResults = @()
        $consolidatedAssignments = @()
        
        foreach ($tenantId in $TenantIds) {
            try {
                Write-LogMessage -Message "Processing tenant: $tenantId" -Level 'Information' -Component 'MultiTenant'
                
                $tenantResult = Start-AzureResourceRBCAudit -TenantId $tenantId -SubscriptionIds $SubscriptionIds -ExportPath $ExportPath -IncludeGroupMembers:$IncludeGroupMembers -IncludeResourceLevel:$IncludeResourceLevel -DryRun:$DryRun
                
                $allTenantResults += [PSCustomObject]@{
                    TenantId = $tenantId
                    Success = $true
                    AssignmentCount = $tenantResult.AssignmentCount
                    ReportPath = $tenantResult.ReportPath
                    SummaryPath = $tenantResult.SummaryPath
                    ErrorMessage = $null
                }
                
                # Collect assignments for consolidated report
                if (-not $DryRun -and $tenantResult.Assignments) {
                    $consolidatedAssignments += $tenantResult.Assignments
                } elseif ($DryRun -and $tenantResult.Assignments) {
                    # In dry-run mode, also collect mock assignments for consolidated reporting
                    $consolidatedAssignments += $tenantResult.Assignments
                }
                
                Write-LogMessage -Message "Completed tenant $($tenantId): $($tenantResult.AssignmentCount) assignments" -Level 'Information' -Component 'MultiTenant'
            }
            catch {
                Write-LogMessage -Message "Failed to process tenant $($tenantId): $($_.Exception.Message)" -Level 'Error' -Component 'MultiTenant'
                
                $allTenantResults += [PSCustomObject]@{
                    TenantId = $tenantId
                    Success = $false
                    AssignmentCount = 0
                    ReportPath = $null
                    SummaryPath = $null
                    ErrorMessage = $_.Exception.Message
                }
            }
        }
        
        # Generate consolidated report
        $consolidatedResult = $null
        if ($DryRun -or ($consolidatedAssignments -and $consolidatedAssignments.Count -gt 0)) {
            # Ensure we have a valid assignments array for PowerShell 5.1 compatibility
            $assignmentsToPass = if ($consolidatedAssignments) { $consolidatedAssignments } else { @() }
            $consolidatedResult = Export-ConsolidatedResourceReport -TenantResults $allTenantResults -Assignments $assignmentsToPass -ExportPath $ExportPath -DryRun:$DryRun
        }
        
        # Export log file
        if (-not $DryRun) {
            Export-LogFile -ExportPath $ExportPath -TenantId "MultiTenant"
        }
        
        # Final summary
        $successCount = ($allTenantResults | Where-Object { $_.Success }).Count
        $failureCount = ($allTenantResults | Where-Object { -not $_.Success }).Count
        $totalAssignments = ($allTenantResults | Measure-Object -Property AssignmentCount -Sum).Sum
        
        Write-LogMessage -Message "Multi-tenant Azure Resource RBAC audit completed!" -Level 'Information' -Component 'MultiTenant'
        Write-LogMessage -Message "Successful tenants: $successCount" -Level 'Information' -Component 'MultiTenant'
        Write-LogMessage -Message "Failed tenants: $failureCount" -Level 'Information' -Component 'MultiTenant'
        Write-LogMessage -Message "Total assignments processed: $totalAssignments" -Level 'Information' -Component 'MultiTenant'
        
        if ($Global:ErrorCount -gt 0) {
            Write-LogMessage -Message "Completed with $($Global:ErrorCount) errors. Check log file for details." -Level 'Warning' -Component 'MultiTenant'
        }
        
        return [PSCustomObject]@{
            TenantResults = $allTenantResults
            ConsolidatedResult = $consolidatedResult
            TotalAssignments = $totalAssignments
            SuccessfulTenants = $successCount
            FailedTenants = $failureCount
        }
    }
    catch {
        Write-LogMessage -Message "Multi-tenant Azure Resource RBAC audit failed: $($_.Exception.Message)" -Level 'Error' -Component 'MultiTenant'
        throw
    }
}

function Export-ConsolidatedResourceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TenantResults,
        
        [Parameter(Mandatory = $true)]
        [array]$Assignments,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        
        if ($DryRun) {
            Write-LogMessage -Message "DRY RUN: Would export consolidated Azure Resource RBAC report to $($ExportPath)" -Level 'Information' -Component 'ConsolidatedExport'
            return [PSCustomObject]@{
                ConsolidatedReportPath = "DRY_RUN_ConsolidatedAzureResourceRBAC_$($timestamp).csv"
                TenantSummaryPath = "DRY_RUN_AzureResourceTenantSummary_$($timestamp).csv"
            }
        }
        
        # Export consolidated assignments
        $consolidatedReportFileName = "ConsolidatedAzureResourceRBAC_$($timestamp).csv"
        $consolidatedReportPath = Join-Path -Path $ExportPath -ChildPath $consolidatedReportFileName
        
        if ($Assignments.Count -gt 0) {
            $sortedAssignments = $Assignments | Sort-Object TenantId, SubscriptionId, Scope, RoleName, PrincipalDisplayName
            $sortedAssignments | Export-Csv -Path $consolidatedReportPath -NoTypeInformation -Encoding UTF8
        }
        
        # Export tenant summary
        $tenantSummaryFileName = "AzureResourceTenantSummary_$($timestamp).csv"
        $tenantSummaryPath = Join-Path -Path $ExportPath -ChildPath $tenantSummaryFileName
        $TenantResults | Export-Csv -Path $tenantSummaryPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage -Message "Consolidated Azure Resource RBAC report exported: $consolidatedReportPath" -Level 'Information' -Component 'ConsolidatedExport'
        Write-LogMessage -Message "Tenant summary exported: $tenantSummaryPath" -Level 'Information' -Component 'ConsolidatedExport'
        
        return [PSCustomObject]@{
            ConsolidatedReportPath = $consolidatedReportPath
            TenantSummaryPath = $tenantSummaryPath
        }
    }
    catch {
        Write-LogMessage -Message "Failed to export consolidated Azure Resource RBAC report: $($_.Exception.Message)" -Level 'Error' -Component 'ConsolidatedExport'
        throw
    }
}
#endregion

#region Main Execution
function Start-AzureResourceRBCAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string[]]$SubscriptionIds,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeGroupMembers,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeResourceLevel,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        Write-LogMessage -Message "Starting Azure Resource RBAC audit for tenant: $TenantId" -Level 'Information' -Component 'SingleTenant'
        
        if ($DryRun) {
            Write-LogMessage -Message "*** DRY RUN MODE - Simulating audit process ***" -Level 'Warning' -Component 'SingleTenant'
        }
        
        # Connect to Azure
        $connectedTenantId = Connect-ToAzure -TenantId $TenantId -DryRun:$DryRun
        
        # Connect to Microsoft Graph
        $graphTenantId = Connect-ToMicrosoftGraph -TenantId $connectedTenantId -RequiredScopes $($ScriptConfig.GraphRequiredScopes) -DryRun:$DryRun
        
        # Detect PIM status
        $isPIMEnabled = Test-AzurePIMEnabled -DryRun:$DryRun
        
        # Initialize assignments array
        $allAssignments = @()
        
        if ($DryRun) {
            # Generate mock data for dry-run
            Write-LogMessage -Message "DRY RUN: Generating mock Azure Resource RBAC assignment data" -Level 'Information' -Component 'SingleTenant'
            
            $allAssignments = @(
                [PSCustomObject]@{
                    AssignmentId = "mock-assignment-1"
                    TenantId = $TenantId
                    PrincipalId = "mock-user-1"
                    PrincipalDisplayName = "Mock User 1"
                    PrincipalType = "User"
                    PrincipalEmail = "mockuser1@tenant.com"
                    RoleId = "mock-role-1"
                    RoleName = "Owner"
                    RoleDescription = "Mock Owner role"
                    AssignmentType = "Direct"
                    AssignmentMethod = "Permanent"
                    Scope = "Subscription"
                    ScopeId = "/subscriptions/mock-sub-1"
                    ScopeName = "Mock Subscription 1"
                    SubscriptionId = "mock-sub-1"
                    PIMStatus = "Not PIM"
                    ActivationStatus = "Active"
                    StartDateTime = ""
                    EndDateTime = ""
                    AssignedBy = ""
                    AssignedDate = ""
                    IsGroupAssignment = $false
                    GroupId = ""
                    GroupName = ""
                    Condition = ""
                    ConditionVersion = ""
                },
                [PSCustomObject]@{
                    AssignmentId = "mock-assignment-2"
                    TenantId = $TenantId
                    PrincipalId = "mock-group-1"
                    PrincipalDisplayName = "Mock Security Group 1"
                    PrincipalType = "Group"
                    PrincipalEmail = "mock-group-1"
                    RoleId = "mock-role-2"
                    RoleName = "Contributor"
                    RoleDescription = "Mock Contributor role"
                    AssignmentType = "PIM"
                    AssignmentMethod = "Eligible"
                    Scope = "ResourceGroup"
                    ScopeId = "/subscriptions/mock-sub-1/resourceGroups/mock-rg-1"
                    ScopeName = "Mock Resource Group 1"
                    SubscriptionId = "mock-sub-1"
                    PIMStatus = "Eligible"
                    ActivationStatus = "Eligible"
                    StartDateTime = (Get-Date).ToString()
                    EndDateTime = (Get-Date).AddDays(30).ToString()
                    AssignedBy = ""
                    AssignedDate = (Get-Date).ToString()
                    IsGroupAssignment = $true
                    GroupId = "mock-group-1"
                    GroupName = "Mock Security Group 1"
                    Condition = ""
                    ConditionVersion = ""
                }
            )
            
            Write-LogMessage -Message "DRY RUN: Generated $($allAssignments.Count) mock assignments" -Level 'Information' -Component 'SingleTenant'
        } else {
            # Get target subscriptions
            $subscriptions = Get-TargetSubscriptions -SubscriptionIds $SubscriptionIds
            
            if ($subscriptions.Count -eq 0) {
                throw "No accessible subscriptions found"
            }
            
            Write-LogMessage -Message "Processing $($subscriptions.Count) subscriptions" -Level 'Information' -Component 'SingleTenant'
            
            # Get management groups
            $managementGroups = Get-ManagementGroups
            Write-LogMessage -Message "Found $($managementGroups.Count) management groups" -Level 'Information' -Component 'SingleTenant'
            
            # Process management group assignments
            foreach ($mg in $managementGroups) {
                try {
                    Write-LogMessage -Message "Processing management group: $($mg.DisplayName)" -Level 'Verbose' -Component 'SingleTenant'
                    
                    # Get role definitions from first subscription for reference
                    $roleDefinitions = Get-AzureRoleDefinitions -SubscriptionId $subscriptions[0].Id
                    
                    # Get direct assignments
                    $mgAssignments = Get-RoleAssignmentsForScope -Scope $mg.Id -ScopeName $mg.DisplayName -ScopeType 'ManagementGroup' -RoleDefinitions $roleDefinitions -SubscriptionId $subscriptions[0].Id
                    
                    # Add TenantId to assignments
                    foreach ($assignment in $mgAssignments) {
                        $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                    }
                    
                    $allAssignments += $mgAssignments
                    
                    # Get PIM assignments if enabled
                    if ($isPIMEnabled) {
                        $mgPimAssignments = Get-PIMRoleAssignmentsForScope -ResourceId $mg.Id -ScopeName $mg.DisplayName -ScopeType 'ManagementGroup' -RoleDefinitions $roleDefinitions -SubscriptionId $subscriptions[0].Id
                        
                        # Add TenantId to PIM assignments
                        foreach ($assignment in $mgPimAssignments) {
                            $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                        }
                        
                        $allAssignments += $mgPimAssignments
                    }
                }
                catch {
                    Write-LogMessage -Message "Error processing management group $($mg.DisplayName): $($_.Exception.Message)" -Level 'Warning' -Component 'SingleTenant'
                }
            }
            
            # Process each subscription
            foreach ($subscription in $subscriptions) {
                try {
                    Write-LogMessage -Message "Processing subscription: $($subscription.Name) ($($subscription.Id))" -Level 'Information' -Component 'SingleTenant'
                    
                    # Get role definitions for this subscription
                    $roleDefinitions = Get-AzureRoleDefinitions -SubscriptionId $subscription.Id
                    
                    # Get subscription-level assignments
                    $subScope = "/subscriptions/$($subscription.Id)"
                    $subAssignments = Get-RoleAssignmentsForScope -Scope $subScope -ScopeName $subscription.Name -ScopeType 'Subscription' -RoleDefinitions $roleDefinitions -SubscriptionId $subscription.Id
                    
                    # Add TenantId to assignments
                    foreach ($assignment in $subAssignments) {
                        $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                    }
                    
                    $allAssignments += $subAssignments
                    
                    # Get PIM assignments if enabled
                    if ($isPIMEnabled) {
                        $subPimAssignments = Get-PIMRoleAssignmentsForScope -ResourceId $subScope -ScopeName $subscription.Name -ScopeType 'Subscription' -RoleDefinitions $roleDefinitions -SubscriptionId $subscription.Id
                        
                        # Add TenantId to PIM assignments
                        foreach ($assignment in $subPimAssignments) {
                            $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                        }
                        
                        $allAssignments += $subPimAssignments
                    }
                    
                    # Get resource groups and process them
                    $resourceGroups = Get-ResourceGroups -SubscriptionId $subscription.Id
                    
                    foreach ($rg in $resourceGroups) {
                        try {
                            $rgScope = "/subscriptions/${subscription}.Id/resourceGroups/${rg}.ResourceGroupName"
                            $rgAssignments = Get-RoleAssignmentsForScope -Scope $rgScope -ScopeName $rg.ResourceGroupName -ScopeType 'ResourceGroup' -RoleDefinitions $roleDefinitions -SubscriptionId $subscription.Id
                            
                            # Add TenantId to assignments
                            foreach ($assignment in $rgAssignments) {
                                $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                            }
                            
                            $allAssignments += $rgAssignments
                            
                            # Get PIM assignments if enabled
                            if ($isPIMEnabled) {
                                $rgPimAssignments = Get-PIMRoleAssignmentsForScope -ResourceId $rgScope -ScopeName $rg.ResourceGroupName -ScopeType 'ResourceGroup' -RoleDefinitions $roleDefinitions -SubscriptionId $subscription.Id
                                
                                # Add TenantId to PIM assignments
                                foreach ($assignment in $rgPimAssignments) {
                                    $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                                }
                                
                                $allAssignments += $rgPimAssignments
                            }
                        }
                        catch {
                            Write-LogMessage -Message "Error processing resource group $($rg.ResourceGroupName): $($_.Exception.Message)" -Level 'Debug' -Component 'SingleTenant'
                        }
                    }
                    
                    # Process resources if requested
                    if ($IncludeResourceLevel) {
                        $resources = Get-Resources -SubscriptionId $subscription.Id
                        
                        foreach ($resource in $resources) {
                            try {
                                $resourceScope = $resource.ResourceId
                                $resourceAssignments = Get-RoleAssignmentsForScope -Scope $resourceScope -ScopeName $resource.Name -ScopeType 'Resource' -RoleDefinitions $roleDefinitions -SubscriptionId $subscription.Id
                                
                                # Add TenantId to assignments
                                foreach ($assignment in $resourceAssignments) {
                                    $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                                }
                                
                                $allAssignments += $resourceAssignments
                                
                                # Get PIM assignments if enabled
                                if ($isPIMEnabled) {
                                    $resourcePimAssignments = Get-PIMRoleAssignmentsForScope -ResourceId $resourceScope -ScopeName $resource.Name -ScopeType 'Resource' -RoleDefinitions $roleDefinitions -SubscriptionId $subscription.Id
                                    
                                    # Add TenantId to PIM assignments
                                    foreach ($assignment in $resourcePimAssignments) {
                                        $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                                    }
                                    
                                    $allAssignments += $resourcePimAssignments
                                }
                            }
                            catch {
                                Write-LogMessage -Message "Error processing resource $($resource.Name): $($_.Exception.Message)" -Level 'Debug' -Component 'SingleTenant'
                            }
                        }
                    }
                }
                catch {
                    Write-LogMessage -Message "Error processing subscription $($subscription.Name): $($_.Exception.Message)" -Level 'Warning' -Component 'SingleTenant'
                }
            }
            
            # Enrich principal information
            Write-LogMessage -Message "Enriching principal information for $($allAssignments.Count) assignments..." -Level 'Information' -Component 'SingleTenant'
            $allAssignments = Get-PrincipalInformation -Assignments $allAssignments
            
            # Handle group member expansion if requested
            if ($IncludeGroupMembers) {
                $groupAssignments = $allAssignments | Where-Object { $_.IsGroupAssignment -eq $true }
                if ($groupAssignments.Count -gt 0) {
                    Write-LogMessage -Message "Expanding group members for $($groupAssignments.Count) group assignments..." -Level 'Information' -Component 'SingleTenant'
                    $memberAssignments = Get-GroupMemberRoleAssignments -GroupAssignments $groupAssignments
                    
                    # Add TenantId to member assignments
                    foreach ($assignment in $memberAssignments) {
                        $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                    }
                    
                    $allAssignments += $memberAssignments
                }
            }
        }
        
        # Export report
        Write-LogMessage -Message "Generating reports..." -Level 'Information' -Component 'SingleTenant'
        $exportResult = Export-ResourceRBACReport -Assignments $allAssignments -ExportPath $ExportPath -TenantId $connectedTenantId -IsPIMEnabled $isPIMEnabled -DryRun:$DryRun
        
        # Final summary for this tenant
        Write-LogMessage -Message "Tenant $TenantId Azure Resource RBAC audit completed successfully!" -Level 'Information' -Component 'SingleTenant'
        Write-LogMessage -Message "Total assignments processed: $($exportResult.AssignmentCount)" -Level 'Information' -Component 'SingleTenant'
        
        if (-not $DryRun) {
            Write-LogMessage -Message "Report saved to: $($exportResult.ReportPath)" -Level 'Information' -Component 'SingleTenant'
            Write-LogMessage -Message "Summary saved to: $($exportResult.SummaryPath)" -Level 'Information' -Component 'SingleTenant'
        }
        
        # Return result with assignments for consolidation
        $result = $exportResult
        $result | Add-Member -NotePropertyName "Assignments" -NotePropertyValue $allAssignments -Force
        
        return $result
    }
    catch {
        Write-LogMessage -Message "Tenant $TenantId Azure Resource RBAC audit failed: $($_.Exception.Message)" -Level 'Error' -Component 'SingleTenant'
        throw
    }
}
#endregion

# Script execution
try {
    $multiTenantResult = Start-MultiTenantAzureResourceRBCAudit -TenantIds $TenantIds -SubscriptionIds $SubscriptionIds -ExportPath $ExportPath -IncludeGroupMembers:$IncludeGroupMembers -IncludeResourceLevel:$IncludeResourceLevel -DryRun:$DryRun
    
    Write-Host "`nMulti-Tenant Azure Resource RBAC Audit Summary:" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "Total Tenants Processed: $($multiTenantResult.TenantResults.Count)" -ForegroundColor White
    Write-Host "Successful Tenants: $($multiTenantResult.SuccessfulTenants)" -ForegroundColor Green
    Write-Host "Failed Tenants: $($multiTenantResult.FailedTenants)" -ForegroundColor $(if ($multiTenantResult.FailedTenants -gt 0) { 'Red' } else { 'Green' })
    Write-Host "Total Assignments: $($multiTenantResult.TotalAssignments)" -ForegroundColor White
    
    if ($DryRun) {
        Write-Host "*** DRY RUN MODE - No actual changes were made ***" -ForegroundColor Yellow
    }
    
    if ($multiTenantResult.ConsolidatedResult) {
        Write-Host "Consolidated Report: $($multiTenantResult.ConsolidatedResult.ConsolidatedReportPath)" -ForegroundColor White
        Write-Host "Tenant Summary: $($multiTenantResult.ConsolidatedResult.TenantSummaryPath)" -ForegroundColor White
    }
    
    if ($Global:ErrorCount -gt 0) {
        Write-Host "Errors Encountered: $($Global:ErrorCount)" -ForegroundColor Yellow
    }
    
    # Display per-tenant results
    Write-Host "`nPer-Tenant Results:" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    foreach ($tenantResult in $multiTenantResult.TenantResults) {
        $statusColor = if ($tenantResult.Success) { 'Green' } else { 'Red' }
        $status = if ($tenantResult.Success) { 'SUCCESS' } else { 'FAILED' }
        Write-Host "Tenant: $($tenantResult.TenantId) - $status ($($tenantResult.AssignmentCount) assignments)" -ForegroundColor $statusColor
        
        if (-not $tenantResult.Success) {
            Write-Host "  Error: $($tenantResult.ErrorMessage)" -ForegroundColor Red
        }
    }
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green
#endregion