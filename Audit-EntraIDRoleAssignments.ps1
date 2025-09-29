#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive audit script for Azure Entra ID role assignments with PIM detection
    
.DESCRIPTION
    This script audits all Azure Entra ID role assignments across the tenant, including:
    - Direct role assignments to users and service principals
    - Group-based role assignments (roles assigned to groups)
    - PIM (Privileged Identity Management) eligible and active assignments
    - Detailed reporting with scope, activation status, and assignment metadata
    
    The script is compatible with PowerShell 5.1 and uses Microsoft Graph API modules.
    
.PARAMETER TenantIds
    Array of Azure Tenant IDs to audit. If not specified, uses the current connected tenant.
    Supports multi-tenant auditing across multiple Azure AD tenants.
    
.PARAMETER DryRun
    Switch to run in dry-run mode. In dry-run mode, the script will simulate the audit process
    without making any actual API calls that could modify data. Useful for testing and validation.
    
.PARAMETER ExportPath
    Directory path where the CSV reports will be saved. Default is current directory.
    
.PARAMETER IncludeGroupMembers
    Switch to include individual group members when roles are assigned to groups.
    
.PARAMETER LogLevel
    Logging verbosity level. Valid values: Error, Warning, Information, Verbose, Debug
    Default: Information
    
.PARAMETER BatchSize
    Number of assignments to process per batch for better performance.
    Default: 50, Range: 1-200
    
.EXAMPLE
    .\Audit-EntraIDRoleAssignments.ps1 -TenantIds @("12345678-1234-1234-1234-123456789012", "87654321-4321-4321-4321-210987654321")
    
.EXAMPLE
    .\Audit-EntraIDRoleAssignments.ps1 -TenantIds @("12345678-1234-1234-1234-123456789012") -ExportPath "C:\Reports" -IncludeGroupMembers -LogLevel Verbose -DryRun
    
.EXAMPLE
    .\Audit-EntraIDRoleAssignments.ps1 -TenantIds @("12345678-1234-1234-1234-123456789012") -ExportPath "C:\Reports" -IncludeGroupMembers -LogLevel Verbose
    
.NOTES
    Author: Azure Audit Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
    Required Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.Governance
    Required Permissions: Directory.Read.All, RoleManagement.Read.All, PrivilegedAccess.Read.AzureAD
    
    MINIMUM API PERMISSIONS:
    - Directory.Read.All (Application/Delegated): Read user, group, service principal information
    - RoleManagement.Read.All (Application/Delegated): Read role definitions and assignments
    - PrivilegedAccess.Read.AzureAD (Application/Delegated): Read PIM data for Azure AD roles
    
    MINIMUM USER ROLES:
    - Global Reader (recommended): Full read access to Azure AD and role assignments
    - Security Reader (minimum): Basic role visibility with limited PIM access
    - Privileged Role Administrator: Required for complete PIM data access
    
    MULTI-TENANT REQUIREMENTS:
    - Application must be registered as multi-tenant
    - Admin consent required in each target tenant
    - User must have appropriate roles in each tenant
    - Cross-tenant guest users may have limited visibility
    
    Multi-Tenant Support: This script supports auditing multiple tenants in a single execution.
    Dry-Run Mode: Use -DryRun to simulate the audit process without making actual API calls.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$TenantIds,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeGroupMembers,
    
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
    Name = 'Audit-EntraIDRoleAssignments'
    Version = '1.0'
    RequiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement', 
        'Microsoft.Graph.Identity.Governance'
    )
    RequiredScopes = @(
        'Directory.Read.All',
        'RoleManagement.Read.All',
        'PrivilegedAccess.Read.AzureAD'
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
        $logFileName = "EntraIDRoleAudit_Log_{0}_{1}.csv" -f $TenantId, $timestamp
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

#region Graph Connection
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
        
        Write-LogMessage -Message "Successfully connected to tenant: $($newContext.TenantId)" -Level 'Information' -Component 'GraphConnection'
        Write-LogMessage -Message "Available scopes: $($newContext.Scopes -join ', ')" -Level 'Verbose' -Component 'GraphConnection'
        
        return $newContext.TenantId
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Microsoft Graph for tenant ${TenantId}: $($_.Exception.Message)" -Level 'Error' -Component 'GraphConnection'
        throw
    }
}
#endregion

#region PIM Detection
function Test-PIMEnabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-LogMessage -Message "DRY RUN: Would check if PIM is enabled in the tenant" -Level 'Information' -Component 'PIMDetection'
        return $true  # Assume PIM is enabled in dry-run mode for testing
    }
    
    try {
        Write-LogMessage -Message "Checking if PIM is enabled in the tenant..." -Level 'Information' -Component 'PIMDetection'
        
        # Try to access PIM role eligibility schedules - if successful, PIM is enabled
        $pimRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Top 1 -ErrorAction SilentlyContinue
        
        if ($pimRoles) {
            Write-LogMessage -Message "PIM is enabled in this tenant" -Level 'Information' -Component 'PIMDetection'
            return $true
        }
        else {
            Write-LogMessage -Message "PIM is not enabled in this tenant" -Level 'Information' -Component 'PIMDetection'
            return $false
        }
    }
    catch {
        Write-LogMessage -Message "Unable to determine PIM status (assuming not enabled): $($_.Exception.Message)" -Level 'Warning' -Component 'PIMDetection'
        return $false
    }
}
#endregion

#region Role Assignment Retrieval
function Get-EntraIDRoleDefinitions {
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Retrieving Entra ID role definitions..." -Level 'Information' -Component 'RoleRetrieval'
        
        $roleDefinitions = @{}
        $roles = Get-MgDirectoryRole -All -ErrorAction Stop
        
        foreach ($role in $roles) {
            $roleDefinitions[$role.Id] = @{
                Id = $role.Id
                DisplayName = $role.DisplayName
                Description = $role.Description
                RoleTemplateId = $role.RoleTemplateId
            }
        }
        
        # Also get role templates for roles that might not be activated yet
        $roleTemplates = Get-MgDirectoryRoleTemplate -All -ErrorAction Stop
        
        foreach ($template in $roleTemplates) {
            if (-not $roleDefinitions.ContainsKey($template.Id)) {
                $roleDefinitions[$template.Id] = @{
                    Id = $template.Id
                    DisplayName = $template.DisplayName
                    Description = $template.Description
                    RoleTemplateId = $template.Id
                    IsTemplate = $true
                }
            }
        }
        
        Write-LogMessage -Message "Retrieved $($roleDefinitions.Count) role definitions" -Level 'Information' -Component 'RoleRetrieval'
        return $roleDefinitions
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve role definitions: $($_.Exception.Message)" -Level 'Error' -Component 'RoleRetrieval'
        throw
    }
}

function Get-DirectRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$RoleDefinitions
    )
    
    try {
        Write-LogMessage -Message "Retrieving direct role assignments..." -Level 'Information' -Component 'RoleRetrieval'
        
        $assignments = @()
        $processedCount = 0
        
        # Get all directory role assignments
        foreach ($roleId in $RoleDefinitions.Keys) {
            try {
                $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId -All -ErrorAction SilentlyContinue
                
                foreach ($member in $roleMembers) {
                    $assignment = [PSCustomObject]@{
                        AssignmentId = [guid]::NewGuid().ToString()
                        PrincipalId = $member.Id
                        PrincipalDisplayName = ''
                        PrincipalType = ''
                        PrincipalEmail = ''
                        RoleId = $roleId
                        RoleName = $RoleDefinitions[$roleId].DisplayName
                        RoleDescription = $RoleDefinitions[$roleId].Description
                        AssignmentType = 'Direct'
                        AssignmentMethod = 'Permanent'
                        Scope = 'Tenant'
                        ScopeId = '/'
                        ScopeName = 'Tenant Root'
                        PIMStatus = 'Not PIM'
                        ActivationStatus = 'Active'
                        StartDateTime = ''
                        EndDateTime = ''
                        AssignedBy = ''
                        AssignedDate = ''
                        IsGroupAssignment = $false
                        GroupId = ''
                        GroupName = ''
                    }
                    
                    $assignments += $assignment
                    $processedCount++
                    
                    if ($processedCount % $BatchSize -eq 0) {
                        Write-LogMessage -Message "Processed $processedCount assignments..." -Level 'Verbose' -Component 'RoleRetrieval'
                    }
                }
            }
            catch {
                Write-LogMessage -Message "Error retrieving members for role $($RoleDefinitions[$roleId].DisplayName): $($_.Exception.Message)" -Level 'Warning' -Component 'RoleRetrieval'
            }
        }
        
        Write-LogMessage -Message "Retrieved $($assignments.Count) direct role assignments" -Level 'Information' -Component 'RoleRetrieval'
        return $assignments
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve direct role assignments: $($_.Exception.Message)" -Level 'Error' -Component 'RoleRetrieval'
        throw
    }
}

function Get-PIMRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$RoleDefinitions
    )
    
    try {
        Write-LogMessage -Message "Retrieving PIM role assignments..." -Level 'Information' -Component 'PIMRetrieval'
        
        $assignments = @()
        
        # Get PIM eligible assignments
        try {
            $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
            
            foreach ($assignment in $eligibleAssignments) {
                $pimAssignment = [PSCustomObject]@{
                    AssignmentId = $assignment.Id
                    PrincipalId = $assignment.PrincipalId
                    PrincipalDisplayName = ''
                    PrincipalType = ''
                    PrincipalEmail = ''
                    RoleId = $assignment.RoleDefinitionId
                    RoleName = ''
                    RoleDescription = ''
                    AssignmentType = 'PIM'
                    AssignmentMethod = 'Eligible'
                    Scope = 'Tenant'
                    ScopeId = '/'
                    ScopeName = 'Tenant Root'
                    PIMStatus = 'Eligible'
                    ActivationStatus = 'Eligible'
                    StartDateTime = $assignment.StartDateTime
                    EndDateTime = $assignment.EndDateTime
                    AssignedBy = ''
                    AssignedDate = $assignment.CreatedDateTime
                    IsGroupAssignment = $false
                    GroupId = ''
                    GroupName = ''
                }
                
                # Try to get role name from definitions
                if ($RoleDefinitions.ContainsKey($assignment.RoleDefinitionId)) {
                    $pimAssignment.RoleName = $RoleDefinitions[$assignment.RoleDefinitionId].DisplayName
                    $pimAssignment.RoleDescription = $RoleDefinitions[$assignment.RoleDefinitionId].Description
                }
                
                $assignments += $pimAssignment
            }
        }
        catch {
            Write-LogMessage -Message "Error retrieving PIM eligible assignments: $($_.Exception.Message)" -Level 'Warning' -Component 'PIMRetrieval'
        }
        
        # Get PIM active assignments
        try {
            $activeAssignments = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop
            
            foreach ($assignment in $activeAssignments) {
                $pimAssignment = [PSCustomObject]@{
                    AssignmentId = $assignment.Id
                    PrincipalId = $assignment.PrincipalId
                    PrincipalDisplayName = ''
                    PrincipalType = ''
                    PrincipalEmail = ''
                    RoleId = $assignment.RoleDefinitionId
                    RoleName = ''
                    RoleDescription = ''
                    AssignmentType = 'PIM'
                    AssignmentMethod = 'Active'
                    Scope = 'Tenant'
                    ScopeId = '/'
                    ScopeName = 'Tenant Root'
                    PIMStatus = 'Active'
                    ActivationStatus = 'Active'
                    StartDateTime = $assignment.StartDateTime
                    EndDateTime = $assignment.EndDateTime
                    AssignedBy = ''
                    AssignedDate = $assignment.CreatedDateTime
                    IsGroupAssignment = $false
                    GroupId = ''
                    GroupName = ''
                }
                
                # Try to get role name from definitions
                if ($RoleDefinitions.ContainsKey($assignment.RoleDefinitionId)) {
                    $pimAssignment.RoleName = $RoleDefinitions[$assignment.RoleDefinitionId].DisplayName
                    $pimAssignment.RoleDescription = $RoleDefinitions[$assignment.RoleDefinitionId].Description
                }
                
                $assignments += $pimAssignment
            }
        }
        catch {
            Write-LogMessage -Message "Error retrieving PIM active assignments: $($_.Exception.Message)" -Level 'Warning' -Component 'PIMRetrieval'
        }
        
        Write-LogMessage -Message "Retrieved $($assignments.Count) PIM role assignments" -Level 'Information' -Component 'PIMRetrieval'
        return $assignments
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve PIM role assignments: $($_.Exception.Message)" -Level 'Error' -Component 'PIMRetrieval'
        throw
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
        $uniquePrincipalIds = $Assignments | Select-Object -ExpandProperty PrincipalId -Unique
        
        foreach ($principalId in $uniquePrincipalIds) {
            try {
                # Try to get user information first
                $user = Get-MgUser -UserId $principalId -Property "Id,DisplayName,UserPrincipalName,UserType,AccountEnabled" -ErrorAction SilentlyContinue
                
                if ($user) {
                    # Update all assignments for this user
                    $userAssignments = $Assignments | Where-Object { $_.PrincipalId -eq $principalId }
                    foreach ($assignment in $userAssignments) {
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
                        $spAssignments = $Assignments | Where-Object { $_.PrincipalId -eq $principalId }
                        foreach ($assignment in $spAssignments) {
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
                            $groupAssignments = $Assignments | Where-Object { $_.PrincipalId -eq $principalId }
                            foreach ($assignment in $groupAssignments) {
                                $assignment.PrincipalDisplayName = $group.DisplayName
                                $assignment.PrincipalType = 'Group'
                                $assignment.PrincipalEmail = $group.Id
                                $assignment.IsGroupAssignment = $true
                                $assignment.GroupId = $group.Id
                                $assignment.GroupName = $group.DisplayName
                            }
                        }
                        else {
                            # Unknown principal type
                            $unknownAssignments = $Assignments | Where-Object { $_.PrincipalId -eq $principalId }
                            foreach ($assignment in $unknownAssignments) {
                                $assignment.PrincipalDisplayName = "Unknown Principal"
                                $assignment.PrincipalType = 'Unknown'
                                $assignment.PrincipalEmail = $principalId
                            }
                            
                            Write-LogMessage -Message "Unknown principal type for ID: $principalId" -Level 'Warning' -Component 'PrincipalEnrichment'
                        }
                    }
                }
                
                $processedCount++
                if ($processedCount % $BatchSize -eq 0) {
                    Write-LogMessage -Message "Processed $processedCount principals..." -Level 'Verbose' -Component 'PrincipalEnrichment'
                }
            }
            catch {
                Write-LogMessage -Message "Error enriching principal $principalId`: $($_.Exception.Message)" -Level 'Warning' -Component 'PrincipalEnrichment'
                
                # Update assignments with error information
                $errorAssignments = $Assignments | Where-Object { $_.PrincipalId -eq $principalId }
                foreach ($assignment in $errorAssignments) {
                    $assignment.PrincipalDisplayName = "Error retrieving info"
                    $assignment.PrincipalType = 'Error'
                    $assignment.PrincipalEmail = $principalId
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
function Export-RoleAssignmentReport {
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
        $reportFileName = "EntraIDRoleAssignments_{0}_{1}.csv" -f $TenantId, $timestamp
        $reportFilePath = Join-Path -Path $ExportPath -ChildPath $reportFileName
        
        if ($DryRun) {
            Write-LogMessage -Message "DRY RUN: Would export role assignment report to: $reportFilePath" -Level 'Information' -Component 'Export'
            Write-LogMessage -Message "DRY RUN: Would export $($Assignments.Count) assignments" -Level 'Information' -Component 'Export'
            
            return @{
                ReportPath = "DRY_RUN_$reportFileName"
                SummaryPath = "DRY_RUN_EntraIDRoleAssignments_Summary_{0}_{1}.csv" -f $TenantId, $timestamp
                AssignmentCount = $Assignments.Count
            }
        }
        
        Write-LogMessage -Message "Exporting role assignment report to: $reportFilePath" -Level 'Information' -Component 'Export'
        
        # Ensure export directory exists
        if (-not (Test-Path -Path $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        }
        
        # Sort assignments for better readability
        $sortedAssignments = $Assignments | Sort-Object RoleName, PrincipalDisplayName, AssignmentType
        
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
            UniqueUsers = ($Assignments | Where-Object { $_.PrincipalType -in @('User', 'Guest User') } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            UniqueServicePrincipals = ($Assignments | Where-Object { $_.PrincipalType -eq 'Service Principal' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            UniqueGroups = ($Assignments | Where-Object { $_.PrincipalType -eq 'Group' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            UniqueRoles = ($Assignments | Select-Object -ExpandProperty RoleId -Unique).Count
            PIMEnabled = $IsPIMEnabled
            ErrorCount = $Global:ErrorCount
        }
        
        $summaryFileName = "EntraIDRoleAssignments_Summary_{0}_{1}.csv" -f $TenantId, $timestamp
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
function Start-MultiTenantEntraIDRoleAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$TenantIds,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeGroupMembers,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        Write-LogMessage -Message "Starting Multi-Tenant Entra ID Role Assignment audit..." -Level 'Information' -Component 'MultiTenant'
        Write-LogMessage -Message "Script Version: $($ScriptConfig.Version)" -Level 'Information' -Component 'MultiTenant'
        
        if ($DryRun) {
            Write-LogMessage -Message "*** RUNNING IN DRY-RUN MODE - NO ACTUAL API CALLS WILL BE MADE ***" -Level 'Warning' -Component 'MultiTenant'
        }
        
        # Test and install required modules
        if (-not $DryRun) {
            if (-not (Test-RequiredModules -RequiredModules $ScriptConfig.RequiredModules)) {
                Install-RequiredModules -RequiredModules $ScriptConfig.RequiredModules
            }
            
            # Import required modules
            Import-RequiredModules -RequiredModules $ScriptConfig.RequiredModules
        } else {
            Write-LogMessage -Message "DRY RUN: Would test and install required modules" -Level 'Information' -Component 'MultiTenant'
        }
        
        # If no tenant IDs specified, get current context
        if (-not $TenantIds -or $TenantIds.Count -eq 0) {
            if ($DryRun) {
                $TenantIds = @("dry-run-tenant-id")
                Write-LogMessage -Message "DRY RUN: Using mock tenant ID" -Level 'Information' -Component 'MultiTenant'
            } else {
                $context = Get-MgContext -ErrorAction SilentlyContinue
                if ($context) {
                    $TenantIds = @($context.TenantId)
                    Write-LogMessage -Message "Using current connected tenant: $($context.TenantId)" -Level 'Information' -Component 'MultiTenant'
                } else {
                    throw "No tenant IDs specified and no current Graph connection found"
                }
            }
        }
        
        Write-LogMessage -Message "Processing $($TenantIds.Count) tenant(s)" -Level 'Information' -Component 'MultiTenant'
        
        $allTenantResults = @()
        $consolidatedAssignments = @()
        $tenantSummaries = @()
        
        foreach ($tenantId in $TenantIds) {
            try {
                Write-LogMessage -Message "Processing tenant: $tenantId" -Level 'Information' -Component 'MultiTenant'
                
                $tenantResult = Start-EntraIDRoleAudit -TenantId $tenantId -ExportPath $ExportPath -IncludeGroupMembers:$IncludeGroupMembers -DryRun:$DryRun
                
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
                
                Write-LogMessage -Message "Completed tenant ${tenantId}: $($tenantResult.AssignmentCount) assignments" -Level 'Information' -Component 'MultiTenant'
            }
            catch {
                Write-LogMessage -Message "Failed to process tenant ${tenantId}: $($_.Exception.Message)" -Level 'Error' -Component 'MultiTenant'
                
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
        if ($consolidatedAssignments.Count -gt 0 -or $DryRun) {
            $consolidatedResult = Export-ConsolidatedReport -TenantResults $allTenantResults -Assignments $consolidatedAssignments -ExportPath $ExportPath -DryRun:$DryRun
        }
        
        # Export log file
        if (-not $DryRun) {
            Export-LogFile -ExportPath $ExportPath -TenantId "MultiTenant"
        }
        
        # Final summary
        $successCount = ($allTenantResults | Where-Object { $_.Success }).Count
        $failureCount = ($allTenantResults | Where-Object { -not $_.Success }).Count
        $totalAssignments = ($allTenantResults | Measure-Object -Property AssignmentCount -Sum).Sum
        
        Write-LogMessage -Message "Multi-tenant audit completed!" -Level 'Information' -Component 'MultiTenant'
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
        Write-LogMessage -Message "Multi-tenant audit failed: $($_.Exception.Message)" -Level 'Error' -Component 'MultiTenant'
        throw
    }
}

function Export-ConsolidatedReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$TenantResults,
        
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [array]$Assignments = @(),
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        
        if ($DryRun) {
            Write-LogMessage -Message "DRY RUN: Would export consolidated report to $ExportPath" -Level 'Information' -Component 'ConsolidatedExport'
            return [PSCustomObject]@{
                ConsolidatedReportPath = "DRY_RUN_ConsolidatedEntraIDRoles_$timestamp.csv"
                TenantSummaryPath = "DRY_RUN_TenantSummary_$timestamp.csv"
            }
        }
        
        # Export consolidated assignments
        $consolidatedReportFileName = "ConsolidatedEntraIDRoles_$timestamp.csv"
        $consolidatedReportPath = Join-Path -Path $ExportPath -ChildPath $consolidatedReportFileName
        
        if ($Assignments.Count -gt 0) {
            $sortedAssignments = $Assignments | Sort-Object TenantId, RoleName, PrincipalDisplayName
            $sortedAssignments | Export-Csv -Path $consolidatedReportPath -NoTypeInformation -Encoding UTF8
            Write-LogMessage -Message "Consolidated assignments exported: $($Assignments.Count) records" -Level 'Information' -Component 'ConsolidatedExport'
        } else {
            # Create empty file with headers only
            "" | Out-File -FilePath $consolidatedReportPath -Encoding UTF8
            Write-LogMessage -Message "No assignments to consolidate - empty report created" -Level 'Information' -Component 'ConsolidatedExport'
        }
        
        # Export tenant summary
        $tenantSummaryFileName = "TenantSummary_$timestamp.csv"
        $tenantSummaryPath = Join-Path -Path $ExportPath -ChildPath $tenantSummaryFileName
        $TenantResults | Export-Csv -Path $tenantSummaryPath -NoTypeInformation -Encoding UTF8
        
        Write-LogMessage -Message "Consolidated report exported: $consolidatedReportPath" -Level 'Information' -Component 'ConsolidatedExport'
        Write-LogMessage -Message "Tenant summary exported: $tenantSummaryPath" -Level 'Information' -Component 'ConsolidatedExport'
        
        return [PSCustomObject]@{
            ConsolidatedReportPath = $consolidatedReportPath
            TenantSummaryPath = $tenantSummaryPath
        }
    }
    catch {
        Write-LogMessage -Message "Failed to export consolidated report: $($_.Exception.Message)" -Level 'Error' -Component 'ConsolidatedExport'
        throw
    }
}
#endregion
function Start-EntraIDRoleAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeGroupMembers,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        Write-LogMessage -Message "Starting Entra ID Role Assignment audit for tenant: $TenantId" -Level 'Information' -Component 'SingleTenant'
        
        if ($DryRun) {
            Write-LogMessage -Message "*** DRY RUN MODE - Simulating audit process ***" -Level 'Warning' -Component 'SingleTenant'
        }
        
        # Connect to Microsoft Graph
        $connectedTenantId = Connect-ToMicrosoftGraph -TenantId $TenantId -RequiredScopes $ScriptConfig.RequiredScopes -DryRun:$DryRun
        
        # Detect PIM status
        $isPIMEnabled = Test-PIMEnabled -DryRun:$DryRun
        
        # Initialize assignments array
        $allAssignments = @()
        
        if ($DryRun) {
            # Generate mock data for dry-run
            Write-LogMessage -Message "DRY RUN: Generating mock role assignment data" -Level 'Information' -Component 'SingleTenant'
            
            $allAssignments = @(
                [PSCustomObject]@{
                    AssignmentId = "mock-assignment-1"
                    TenantId = $TenantId
                    PrincipalId = "mock-user-1"
                    PrincipalDisplayName = "Mock User 1"
                    PrincipalType = "User"
                    PrincipalEmail = "mockuser1@tenant.com"
                    RoleId = "mock-role-1"
                    RoleName = "Global Administrator"
                    RoleDescription = "Mock Global Administrator role"
                    AssignmentType = "Direct"
                    AssignmentMethod = "Permanent"
                    Scope = "Tenant"
                    ScopeId = "/"
                    ScopeName = "Tenant Root"
                    PIMStatus = "Not PIM"
                    ActivationStatus = "Active"
                    StartDateTime = ""
                    EndDateTime = ""
                    AssignedBy = ""
                    AssignedDate = ""
                    IsGroupAssignment = $false
                    GroupId = ""
                    GroupName = ""
                },
                [PSCustomObject]@{
                    AssignmentId = "mock-assignment-2"
                    TenantId = $TenantId
                    PrincipalId = "mock-sp-1"
                    PrincipalDisplayName = "Mock Service Principal 1"
                    PrincipalType = "Service Principal"
                    PrincipalEmail = "mock-app-id"
                    RoleId = "mock-role-2"
                    RoleName = "Application Administrator"
                    RoleDescription = "Mock Application Administrator role"
                    AssignmentType = "PIM"
                    AssignmentMethod = "Eligible"
                    Scope = "Tenant"
                    ScopeId = "/"
                    ScopeName = "Tenant Root"
                    PIMStatus = "Eligible"
                    ActivationStatus = "Eligible"
                    StartDateTime = (Get-Date).ToString()
                    EndDateTime = (Get-Date).AddDays(30).ToString()
                    AssignedBy = ""
                    AssignedDate = (Get-Date).ToString()
                    IsGroupAssignment = $false
                    GroupId = ""
                    GroupName = ""
                }
            )
            
            Write-LogMessage -Message "DRY RUN: Generated $($allAssignments.Count) mock assignments" -Level 'Information' -Component 'SingleTenant'
        } else {
            # Get role definitions
            $roleDefinitions = Get-EntraIDRoleDefinitions
            
            # Get direct role assignments
            Write-LogMessage -Message "Retrieving direct role assignments..." -Level 'Information' -Component 'SingleTenant'
            $directAssignments = Get-DirectRoleAssignments -RoleDefinitions $roleDefinitions
            
            # Add TenantId to all assignments
            foreach ($assignment in $directAssignments) {
                $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
            }
            
            # Get PIM role assignments if PIM is enabled
            $pimAssignments = @()
            if ($isPIMEnabled) {
                Write-LogMessage -Message "Retrieving PIM role assignments..." -Level 'Information' -Component 'SingleTenant'
                $pimAssignments = Get-PIMRoleAssignments -RoleDefinitions $roleDefinitions
                
                # Add TenantId to PIM assignments
                foreach ($assignment in $pimAssignments) {
                    $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
                }
            }
            
            # Combine all assignments
            $allAssignments += $directAssignments
            $allAssignments += $pimAssignments
            
            # Enrich principal information
            Write-LogMessage -Message "Enriching principal information..." -Level 'Information' -Component 'SingleTenant'
            $allAssignments = Get-PrincipalInformation -Assignments $allAssignments
            
            # Handle group member expansion if requested
            if ($IncludeGroupMembers) {
                $groupAssignments = $allAssignments | Where-Object { $_.IsGroupAssignment -eq $true }
                if ($groupAssignments.Count -gt 0) {
                    Write-LogMessage -Message "Expanding group members..." -Level 'Information' -Component 'SingleTenant'
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
        $exportResult = Export-RoleAssignmentReport -Assignments $allAssignments -ExportPath $ExportPath -TenantId $connectedTenantId -IsPIMEnabled $isPIMEnabled -DryRun:$DryRun
        
        # Final summary for this tenant
        Write-LogMessage -Message "Tenant $TenantId audit completed successfully!" -Level 'Information' -Component 'SingleTenant'
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
        Write-LogMessage -Message "Tenant $TenantId audit failed: $($_.Exception.Message)" -Level 'Error' -Component 'SingleTenant'
        throw
    }
}
#endregion

# Script execution
try {
    $multiTenantResult = Start-MultiTenantEntraIDRoleAudit -TenantIds $TenantIds -ExportPath $ExportPath -IncludeGroupMembers:$IncludeGroupMembers -DryRun:$DryRun
    
    Write-Host "`nMulti-Tenant Audit Summary:" -ForegroundColor Green
    Write-Host "===========================" -ForegroundColor Green
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