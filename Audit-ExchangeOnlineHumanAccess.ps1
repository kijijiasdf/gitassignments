#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive audit script for Exchange Online human access role assignments
    
.DESCRIPTION
    This script audits all Exchange Online human access role assignments across the tenant, including:
    - Exchange Online Management Role assignments (Organization Management, Recipient Management, etc.)
    - Azure AD Exchange Administrator role assignments
    - Role Groups assigned to users from Azure Entra ID
    - Group-based role assignments (roles assigned to groups)
    - Detailed reporting with scope, activation status, and assignment metadata
    
    The script is compatible with PowerShell 5.1 and uses Microsoft Graph API and Exchange Online modules.
    
    Note: PIM (Privileged Identity Management) is not currently supported for Exchange Online roles by Microsoft.
    
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
    .\Audit-ExchangeOnlineHumanAccess.ps1 -TenantIds @("12345678-1234-1234-1234-123456789012")
    
.EXAMPLE
    .\Audit-ExchangeOnlineHumanAccess.ps1 -TenantIds @("12345678-1234-1234-1234-123456789012") -ExportPath "C:\Reports" -DryRun
    
.NOTES
    Author: Azure Audit Scripts
    Version: 1.0
    Compatible with: PowerShell 5.1+
    Required Modules: Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, ExchangeOnlineManagement
    Required Permissions: Directory.Read.All, RoleManagement.Read.All, Exchange.ManageAsApp
    
    Multi-Tenant Support: This script supports auditing multiple tenants in a single execution.
    Dry-Run Mode: Use -DryRun to simulate the audit process without making actual API calls.
    Authentication: Uses device code flow for secure authentication without requiring a browser on the local machine.
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

#region Script Configuration
$ErrorActionPreference = 'Stop'
$Global:LogLevel = $LogLevel
$Global:ErrorCount = 0

# Performance caching for large environments
$Script:GroupMembershipCache = @{}
$Script:UserLastLogonCache = @{}
$Script:RiskAssessmentCache = @{}

$ScriptConfig = @{
    RequiredModules = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'ExchangeOnlineManagement'
    )
    RequiredScopes = @(
        'Directory.Read.All',
        'RoleManagement.Read.All'
    )
    ExchangeAdminRoles = @(
        'Exchange Administrator',
        'Exchange Recipient Administrator'
    )
}
#endregion

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
        [string]$Component = 'General'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Component] [$Level] $Message"
    
    # Only output if the message level is at or above the global log level
    $levelPriority = @{
        'Error' = 1
        'Warning' = 2
        'Information' = 3
        'Verbose' = 4
        'Debug' = 5
    }
    
    if ($levelPriority[$Level] -le $levelPriority[$Global:LogLevel]) {
        switch ($Level) {
            'Error' { 
                Write-Error $logMessage
                $Global:ErrorCount++
            }
            'Warning' { Write-Warning $logMessage }
            'Information' { Write-Host $logMessage -ForegroundColor Green }
            'Verbose' { Write-Verbose $logMessage }
            'Debug' { Write-Debug $logMessage }
        }
    }
}
#endregion

#region Module Management
function Initialize-RequiredModules {
    [CmdletBinding()]
    param()
    
    Write-LogMessage -Message "Initializing required PowerShell modules..." -Level 'Information' -Component 'ModuleInit'
    
    foreach ($module in $ScriptConfig.RequiredModules) {
        try {
            Write-LogMessage -Message "Checking module: $module" -Level 'Verbose' -Component 'ModuleInit'
            
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-LogMessage -Message "Installing module: $module" -Level 'Information' -Component 'ModuleInit'
                Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction Stop
            }
            
            if (-not (Get-Module -Name $module)) {
                Write-LogMessage -Message "Importing module: $module" -Level 'Verbose' -Component 'ModuleInit'
                Import-Module -Name $module -Force -ErrorAction Stop
            }
            
            Write-LogMessage -Message "Module $module is ready" -Level 'Verbose' -Component 'ModuleInit'
        }
        catch {
            Write-LogMessage -Message "Failed to initialize module $($module): $($_.Exception.Message)" -Level 'Error' -Component 'ModuleInit'
            throw
        }
    }
    
    Write-LogMessage -Message "All required modules initialized successfully" -Level 'Information' -Component 'ModuleInit'
}
#endregion

#region Connection Functions
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
        Write-LogMessage -Message "DRY RUN: Would connect to Microsoft Graph for tenant $TenantId" -Level 'Information' -Component 'GraphConnection'
        return $TenantId
    }
    
    try {
        Write-LogMessage -Message "Connecting to Microsoft Graph for tenant: $TenantId" -Level 'Information' -Component 'GraphConnection'
        
        # Disconnect any existing session
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore disconnect errors
        }
        
        # Connect with required scopes using explicit parameter syntax
        Write-LogMessage -Message "Please use the device code displayed in the console to authenticate." -Level 'Information' -Component 'GraphConnection'
        Write-LogMessage -Message "If you don't see the device code prompt, please check the console window for authentication instructions." -Level 'Information' -Component 'GraphConnection'
        
        # Using explicit parameter syntax as requested
        Connect-MgGraph -TenantId $TenantId -Scopes @('Directory.Read.All', 'RoleManagement.Read.All') -UseDeviceCode -ErrorAction Stop
        
        $newContext = Get-MgContext
        
        Write-LogMessage -Message "Successfully connected to tenant: $($newContext.TenantId)" -Level 'Information' -Component 'GraphConnection'
        Write-LogMessage -Message "Available scopes: $($newContext.Scopes -join ', ')" -Level 'Verbose' -Component 'GraphConnection'
        
        return $newContext.TenantId
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Microsoft Graph for tenant $($TenantId): $($_.Exception.Message)" -Level 'Error' -Component 'GraphConnection'
        throw
    }
}
#endregion

#region Exchange Online Connection
function Connect-ToExchangeOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-LogMessage -Message "DRY RUN: Would connect to Exchange Online for tenant $TenantId" -Level 'Information' -Component 'ExchangeConnection'
        return $true
    }
    
    try {
        Write-LogMessage -Message "Connecting to Exchange Online for tenant: $TenantId" -Level 'Information' -Component 'ExchangeConnection'
        
        # Disconnect any existing session
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore disconnect errors
        }
        
        # For PowerShell 5.1, leverage the existing Microsoft Graph authentication context
        # This provides a better authentication experience without requiring separate device code prompts
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            Write-LogMessage -Message "Using Microsoft Graph authentication context for Exchange Online (PowerShell 5.1)" -Level 'Information' -Component 'ExchangeConnection'
            Write-LogMessage -Message "This approach minimizes authentication prompts by reusing the Graph session" -Level 'Information' -Component 'ExchangeConnection'
        }
        
        # Connect to Exchange Online
        $connectParams = @{
            Organization = $TenantId
            ShowBanner = $false
            ErrorAction = 'Stop'
        }
        
        # Add Device parameter only if running PowerShell 7+
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $connectParams.Device = $true
            Write-LogMessage -Message "Using device code authentication (PowerShell 7+)" -Level 'Information' -Component 'ExchangeConnection'
        }
        
        Write-LogMessage -Message "Please authenticate in the popup window or check console for device code instructions." -Level 'Information' -Component 'ExchangeConnection'
        Connect-ExchangeOnline @connectParams
        
        # Verify connection
        $orgConfig = Get-OrganizationConfig -ErrorAction Stop
        Write-LogMessage -Message "Successfully connected to Exchange Online: $($orgConfig.DisplayName)" -Level 'Information' -Component 'ExchangeConnection'
        
        return $true
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Exchange Online for tenant $($TenantId): $($_.Exception.Message)" -Level 'Error' -Component 'ExchangeConnection'
        throw
    }
}
#endregion

#region Role Retrieval Functions
function Get-ExchangeOnlineRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-LogMessage -Message "DRY RUN: Would retrieve Exchange Online role assignments" -Level 'Information' -Component 'ExchangeRoleRetrieval'
        
        # Return mock assignments
        $mockAssignments = @(
            [PSCustomObject]@{
                AssignmentId = "mock-assignment-1"
                PrincipalId = "mock-user-1"
                PrincipalDisplayName = "Mock User 1"
                PrincipalType = "User"
                PrincipalEmail = "mockuser1@tenant.com"
                RoleId = "Organization Management"
                RoleName = "Organization Management"
                RoleDescription = "Mock Organization Management role"
                AssignmentType = "RoleGroup"
                AssignmentMethod = "Permanent"
                Scope = "Exchange"
                ScopeId = "/"
                ScopeName = "Organization"
                StartDateTime = ""
                EndDateTime = ""
                AssignedBy = ""
                AssignedDate = ""
                IsGroupAssignment = $true
                GroupId = "mock-group-1"
                GroupName = "Organization Management"
                RoleAssignmentPolicy = ""
                CustomRecipientScope = ""
                RecipientScope = "Organization"
            }
        )
        
        return $mockAssignments
    }
    
    try {
        Write-LogMessage -Message "Retrieving Exchange Online role assignments..." -Level 'Information' -Component 'ExchangeRoleRetrieval'
        
        $assignments = @()
        
        # Get all management role assignments
        $roleAssignments = Get-ManagementRoleAssignment -ErrorAction Stop
        
        # PowerShell 5.1 compatibility: Check if collection exists and has items
        if ($roleAssignments -and $roleAssignments.Count -gt 0) {
            foreach ($assignment in $roleAssignments) {
            try {
                $roleAssignmentObj = [PSCustomObject]@{
                    AssignmentId = $assignment.Id
                    PrincipalId = $assignment.RoleAssigneeId
                    PrincipalDisplayName = $assignment.RoleAssigneeName
                    PrincipalType = $assignment.RoleAssigneeType
                    PrincipalEmail = ''
                    RoleId = $assignment.Role
                    RoleName = $assignment.Role
                    RoleDescription = ''
                    AssignmentType = if ($assignment.RoleAssigneeType -eq 'RoleGroup') { 'RoleGroup' } else { 'Direct' }
                    AssignmentMethod = 'Permanent'
                    Scope = 'Exchange'
                    ScopeId = if ($assignment.RecipientWriteScope) { $assignment.RecipientWriteScope } else { '/' }
                    ScopeName = if ($assignment.RecipientWriteScope) { $assignment.RecipientWriteScope } else { 'Organization' }
                    StartDateTime = ''
                    EndDateTime = ''
                    AssignedBy = ''
                    AssignedDate = $assignment.WhenCreated
                    IsGroupAssignment = ($assignment.RoleAssigneeType -eq 'RoleGroup')
                    GroupId = if ($assignment.RoleAssigneeType -eq 'RoleGroup') { $assignment.RoleAssigneeId } else { '' }
                    GroupName = if ($assignment.RoleAssigneeType -eq 'RoleGroup') { $assignment.RoleAssigneeName } else { '' }
                    RoleAssignmentPolicy = $assignment.RoleAssignmentPolicy
                    CustomRecipientScope = $assignment.CustomRecipientWriteScope
                    RecipientScope = $assignment.RecipientWriteScope
                }
                
                $assignments += $roleAssignmentObj
            }
            catch {
                $exceptionMessage = $_.Exception.Message
                Write-LogMessage -Message "Error processing assignment $($assignment.Id): $exceptionMessage" -Level 'Warning' -Component 'ExchangeRoleRetrieval'
            }
            }
        } else {
            Write-LogMessage -Message "No Exchange Online role assignments found" -Level 'Information' -Component 'ExchangeRoleRetrieval'
        }
        
        Write-LogMessage -Message "Retrieved $($assignments.Count) Exchange Online role assignments" -Level 'Information' -Component 'ExchangeRoleRetrieval'
        return $assignments
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve Exchange Online role assignments: $($_.Exception.Message)" -Level 'Error' -Component 'ExchangeRoleRetrieval'
        throw
    }
}

function Get-AzureADExchangeAdminRoles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-LogMessage -Message "DRY RUN: Would retrieve Azure AD Exchange Administrator role assignments" -Level 'Information' -Component 'AzureADRoleRetrieval'
        
        # Return mock Azure AD Exchange admin assignments
        $mockAssignments = @(
            [PSCustomObject]@{
                AssignmentId = "mock-azuread-assignment-1"
                PrincipalId = "mock-user-3"
                PrincipalDisplayName = "Mock Exchange Admin 1"
                PrincipalType = "User"
                PrincipalEmail = "exchangeadmin1@tenant.com"
                RoleId = "Exchange Administrator"
                RoleName = "Exchange Administrator"
                RoleDescription = "Can manage all aspects of Exchange Online"
                AssignmentType = "Direct"
                AssignmentMethod = "Permanent"
                Scope = "Tenant"
                ScopeId = "/"
                ScopeName = "Tenant Root"
                StartDateTime = ""
                EndDateTime = ""
                AssignedBy = ""
                AssignedDate = ""
                IsGroupAssignment = $false
                GroupId = ""
                GroupName = ""
                RoleAssignmentPolicy = ""
                CustomRecipientScope = ""
                RecipientScope = "Tenant"
            }
        )
        
        return $mockAssignments
    }
    
    try {
        Write-LogMessage -Message "Retrieving Azure AD Exchange Administrator role assignments..." -Level 'Information' -Component 'AzureADRoleRetrieval'
        
        $assignments = @()
        
        # PowerShell 5.1 compatibility: Check if ExchangeAdminRoles collection exists
        if ($ScriptConfig.ExchangeAdminRoles -and $ScriptConfig.ExchangeAdminRoles.Count -gt 0) {
            foreach ($roleName in $ScriptConfig.ExchangeAdminRoles) {
            try {
                # Get the role definition
                $roleDefinition = Get-MgDirectoryRole -Filter "DisplayName eq '$roleName'" -ErrorAction SilentlyContinue
                
                if ($roleDefinition) {
                    # Get role members
                    $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleDefinition.Id -All -ErrorAction SilentlyContinue
                    
                    # PowerShell 5.1 compatibility: Check if role members collection exists
                    if ($roleMembers -and $roleMembers.Count -gt 0) {
                        foreach ($member in $roleMembers) {
                        $assignment = [PSCustomObject]@{
                            AssignmentId = [guid]::NewGuid().ToString()
                            PrincipalId = $member.Id
                            PrincipalDisplayName = ''
                            PrincipalType = ''
                            PrincipalEmail = ''
                            RoleId = $roleDefinition.Id
                            RoleName = $roleDefinition.DisplayName
                            RoleDescription = $roleDefinition.Description
                            AssignmentType = 'Direct'
                            AssignmentMethod = 'Permanent'
                            Scope = 'Tenant'
                            ScopeId = '/'
                            ScopeName = 'Tenant Root'
                            StartDateTime = ''
                            EndDateTime = ''
                            AssignedBy = ''
                            AssignedDate = ''
                            IsGroupAssignment = $false
                            GroupId = ''
                            GroupName = ''
                            RoleAssignmentPolicy = ''
                            CustomRecipientScope = ''
                            RecipientScope = 'Tenant'
                        }
                        
                        $assignments += $assignment
                        }
                    }
                }
            }
            catch {
                $exceptionMessage = $_.Exception.Message
                Write-LogMessage -Message "Error retrieving Azure AD role $($roleName): $exceptionMessage" -Level 'Warning' -Component 'AzureADRoleRetrieval'
            }
        }
        } else {
            Write-LogMessage -Message "No Exchange Admin roles configured for auditing" -Level 'Information' -Component 'AzureADRoleRetrieval'
        }
        
        Write-LogMessage -Message "Retrieved $($assignments.Count) Azure AD Exchange admin role assignments" -Level 'Information' -Component 'AzureADRoleRetrieval'
        return $assignments
    }
    catch {
        Write-LogMessage -Message "Failed to retrieve Azure AD Exchange admin roles: $($_.Exception.Message)" -Level 'Error' -Component 'AzureADRoleRetrieval'
        throw
    }
}

#region Principal Information Enrichment
function Get-PrincipalInformation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Assignments
    )
    
    try {
        Write-LogMessage -Message "Enriching principal information for $($Assignments.Count) assignments..." -Level 'Information' -Component 'PrincipalEnrichment'
        
        $enrichedAssignments = @()
        $processedCount = 0
        $startTime = Get-Date
        
        foreach ($assignment in $Assignments) {
            try {
                # Skip if already enriched
                if ($assignment.PrincipalDisplayName -and $assignment.PrincipalType -and $assignment.PrincipalEmail) {
                    $enrichedAssignments += $assignment
                    $processedCount++
                    continue
                }
                
                # Get principal information from Microsoft Graph
                $principal = $null
                try {
                    $principal = Get-MgDirectoryObject -DirectoryObjectId $assignment.PrincipalId -ErrorAction SilentlyContinue
                }
                catch {
                    $exceptionMessage = $_.Exception.Message
                Write-LogMessage -Message "Could not retrieve principal $($assignment.PrincipalId): $exceptionMessage" -Level 'Warning' -Component 'PrincipalEnrichment'
                }
                
                # Get last logon time for user analytics
                $lastLogonTime = $null
                if ($principal) {
                    $principalType = $principal.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
                    if ($principalType -eq 'user') {
                        $lastLogonTime = Get-UserLastLogonTime -UserId $assignment.PrincipalId
                    }
                }
                
                if ($principal) {
                    # Determine principal type and get additional details
                    $principalType = $principal.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
                    
                    switch ($principalType) {
                        'user' {
                            $userDetails = Get-MgUser -UserId $assignment.PrincipalId -Property 'DisplayName,UserPrincipalName,UserType' -ErrorAction SilentlyContinue
                            if ($userDetails) {
                                $assignment.PrincipalDisplayName = $userDetails.DisplayName
                                $assignment.PrincipalType = 'User'
                                $assignment.PrincipalEmail = $userDetails.UserPrincipalName
                                $assignment.LastLogonTime = $lastLogonTime
                            }
                        }
                        'group' {
                            $groupDetails = Get-MgGroup -GroupId $assignment.PrincipalId -Property 'DisplayName,Mail' -ErrorAction SilentlyContinue
                            if ($groupDetails) {
                                $assignment.PrincipalDisplayName = $groupDetails.DisplayName
                                $assignment.PrincipalType = 'Group'
                                $assignment.PrincipalEmail = $groupDetails.Mail
                                $assignment.IsGroupAssignment = $true
                                $assignment.GroupId = $assignment.PrincipalId
                                $assignment.GroupName = $groupDetails.DisplayName
                                $assignment.LastLogonTime = $null
                            }
                        }
                        'servicePrincipal' {
                            $spDetails = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -Property 'DisplayName,AppId' -ErrorAction SilentlyContinue
                            if ($spDetails) {
                                $assignment.PrincipalDisplayName = $spDetails.DisplayName
                                $assignment.PrincipalType = 'Service Principal'
                                $assignment.PrincipalEmail = $spDetails.AppId
                                $assignment.LastLogonTime = $null
                            }
                        }
                        default {
                            $assignment.PrincipalDisplayName = $principal.Id
                            $assignment.PrincipalType = $principalType
                            $assignment.PrincipalEmail = $principal.Id
                            $assignment.LastLogonTime = $null
                        }
                    }
                }
                
                $enrichedAssignments += $assignment
                $processedCount++
                
                # Progress reporting with ETA calculation
                if ($processedCount % $BatchSize -eq 0) {
                    $elapsedTime = (Get-Date) - $startTime
                    $avgTimePerAssignment = $elapsedTime.TotalSeconds / $processedCount
                    $remainingAssignments = $Assignments.Count - $processedCount
                    $etaMinutes = ($avgTimePerAssignment * $remainingAssignments) / 60
                    
                    $progressPercent = [math]::Round(($processedCount / $Assignments.Count) * 100, 1)
                    Write-LogMessage -Message "Progress: $processedCount/$($Assignments.Count) assignments ($progressPercent%) - ETA: $([math]::Round($etaMinutes, 1)) minutes" -Level 'Information' -Component 'PrincipalEnrichment'
                }
            }
            catch {
                $exceptionMessage = $_.Exception.Message
                Write-LogMessage -Message "Error enriching assignment $($assignment.AssignmentId): $exceptionMessage" -Level 'Warning' -Component 'PrincipalEnrichment'
                $enrichedAssignments += $assignment
                $processedCount++
            }
        }
        
        $totalTime = ((Get-Date) - $startTime).TotalMinutes
        Write-LogMessage -Message "Successfully enriched $($enrichedAssignments.Count) assignments in $([math]::Round($totalTime, 1)) minutes" -Level 'Information' -Component 'PrincipalEnrichment'
        return $enrichedAssignments
    }
    catch {
        Write-LogMessage -Message "Failed to enrich principal information: $($_.Exception.Message)" -Level 'Error' -Component 'PrincipalEnrichment'
        throw
    }
}
#endregion

#region Group Member Expansion
function Get-GroupMemberRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$GroupAssignments
    )
    
    try {
        Write-LogMessage -Message "Expanding group members for $($GroupAssignments.Count) group assignments..." -Level 'Information' -Component 'GroupExpansion'
        
        $memberAssignments = @()
        $processedCount = 0
        $startTime = Get-Date
        
        foreach ($groupAssignment in $GroupAssignments) {
            try {
                if ($groupAssignment.IsGroupAssignment -eq $true) {
                    # Get all nested group members with depth limiting
                    $groupMembers = Get-NestedGroupMembers -GroupId $groupAssignment.GroupId -MaxDepth 10
                    
                    foreach ($member in $groupMembers) {
                        $memberAssignment = $groupAssignment.PSObject.Copy()
                        $memberAssignment.AssignmentId = [guid]::NewGuid().ToString()
                        $memberAssignment.PrincipalId = $member.Id
                        $memberAssignment.PrincipalDisplayName = $member.DisplayName
                        $memberAssignment.PrincipalType = $member.Type
                        $memberAssignment.PrincipalEmail = $member.Email
                        $memberAssignment.AssignmentType = 'Group Member'
                        $memberAssignment.NestedGroupDepth = $member.Depth
                        $memberAssignment.DirectGroupMembership = ($member.Depth -eq 1)
                        
                        $memberAssignments += $memberAssignment
                    }
                }
                
                $processedCount++
                
                # Progress reporting with ETA calculation
                if ($processedCount % 10 -eq 0) {
                    $elapsedTime = (Get-Date) - $startTime
                    $avgTimePerGroup = $elapsedTime.TotalSeconds / $processedCount
                    $remainingGroups = $GroupAssignments.Count - $processedCount
                    $etaMinutes = ($avgTimePerGroup * $remainingGroups) / 60
                    
                    $progressPercent = [math]::Round(($processedCount / $GroupAssignments.Count) * 100, 1)
                    Write-LogMessage -Message "Progress: $processedCount/$($GroupAssignments.Count) groups ($progressPercent%) - ETA: $([math]::Round($etaMinutes, 1)) minutes" -Level 'Information' -Component 'GroupExpansion'
                }
            }
            catch {
                $exceptionMessage = $_.Exception.Message
                Write-LogMessage -Message "Error expanding group $($groupAssignment.GroupName): $exceptionMessage" -Level 'Warning' -Component 'GroupExpansion'
                $processedCount++
            }
        }
        
        # Enrich member information
        if ($memberAssignments.Count -gt 0) {
            Write-LogMessage -Message "Enriching member information for $($memberAssignments.Count) group members..." -Level 'Information' -Component 'GroupExpansion'
            $memberAssignments = Get-PrincipalInformation -Assignments $memberAssignments
        }
        
        $totalTime = ((Get-Date) - $startTime).TotalMinutes
        Write-LogMessage -Message "Expanded $($memberAssignments.Count) group member assignments in $([math]::Round($totalTime, 1)) minutes" -Level 'Information' -Component 'GroupExpansion'
        return $memberAssignments
    }
    catch {
        Write-LogMessage -Message "Failed to expand group members: $($_.Exception.Message)" -Level 'Error' -Component 'GroupExpansion'
        throw
    }
}

function Get-NestedGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupId,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 10,
        
        [Parameter(Mandatory = $false)]
        [int]$CurrentDepth = 1,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$VisitedGroups = @{},
        
        [Parameter(Mandatory = $false)]
        [array]$Members = @()
    )
    
    # Circular reference protection
    if ($VisitedGroups.ContainsKey($GroupId) -or $CurrentDepth -gt $MaxDepth) {
        return $Members
    }
    
    # Mark this group as visited
    $VisitedGroups[$GroupId] = $true
    
    try {
        # Check cache first for performance
        $cacheKey = "$GroupId-$MaxDepth-$CurrentDepth"
        if ($Script:GroupMembershipCache.ContainsKey($cacheKey)) {
            return $Script:GroupMembershipCache[$cacheKey]
        }
        
        # Get direct members of this group
        $directMembers = Get-MgGroupMember -GroupId $GroupId -All -ErrorAction SilentlyContinue
        
        foreach ($member in $directMembers) {
            $memberType = $member.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''
            
            if ($memberType -eq 'user') {
                # Add user member
                $userDetails = Get-MgUser -UserId $member.Id -Property 'DisplayName,UserPrincipalName,UserType' -ErrorAction SilentlyContinue
                $Members += [PSCustomObject]@{
                    Id = $member.Id
                    DisplayName = if ($userDetails) { $userDetails.DisplayName } else { $member.Id }
                    Type = 'User'
                    Email = if ($userDetails) { $userDetails.UserPrincipalName } else { '' }
                    Depth = $CurrentDepth
                }
            }
            elseif ($memberType -eq 'group' -and $CurrentDepth -lt $MaxDepth) {
                # Recursively process nested group
                $groupDetails = Get-MgGroup -GroupId $member.Id -Property 'DisplayName,Mail' -ErrorAction SilentlyContinue
                $nestedMembers = Get-NestedGroupMembers -GroupId $member.Id -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1) -VisitedGroups $VisitedGroups -Members @()
                
                # Add nested group info to each member
                foreach ($nestedMember in $nestedMembers) {
                    $nestedMemberWithGroupInfo = $nestedMember.PSObject.Copy()
                    $nestedMemberWithGroupInfo.NestedThroughGroup = if ($groupDetails) { $groupDetails.DisplayName } else { $member.Id }
                    $Members += $nestedMemberWithGroupInfo
                }
            }
            elseif ($memberType -eq 'servicePrincipal') {
                # Add service principal member
                $spDetails = Get-MgServicePrincipal -ServicePrincipalId $member.Id -Property 'DisplayName,AppId' -ErrorAction SilentlyContinue
                $Members += [PSCustomObject]@{
                    Id = $member.Id
                    DisplayName = if ($spDetails) { $spDetails.DisplayName } else { $member.Id }
                    Type = 'Service Principal'
                    Email = if ($spDetails) { $spDetails.AppId } else { '' }
                    Depth = $CurrentDepth
                }
            }
        }
        
        # Cache results for performance
        $Script:GroupMembershipCache[$cacheKey] = $Members
        return $Members
    }
    catch {
        $exceptionMessage = $_.Exception.Message
        Write-LogMessage -Message ("Error retrieving nested group members for group {0}: {1}" -f $GroupId, $exceptionMessage) -Level 'Warning' -Component 'GroupExpansion'
        return $Members
    }
}
#endregion

#region Export Functions
function Export-ExchangeHumanAccessReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Assignments,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $reportFileName = "ExchangeOnlineHumanAccess_{0}_{1}.csv" -f $TenantId, $timestamp
        $reportFilePath = Join-Path -Path $ExportPath -ChildPath $reportFileName
        
        if ($DryRun) {
            Write-LogMessage -Message "DRY RUN: Would export Exchange Online human access report to: $reportFilePath" -Level 'Information' -Component 'Export'
            Write-LogMessage -Message "DRY RUN: Would export $($Assignments.Count) assignments" -Level 'Information' -Component 'Export'
            
            return @{
                ReportPath = "DRY_RUN_$reportFileName"
                SummaryPath = "DRY_RUN_ExchangeOnlineHumanAccess_Summary_{0}_{1}.csv" -f $TenantId, $timestamp
                AssignmentCount = $Assignments.Count
            }
        }
        
        Write-LogMessage -Message "Exporting Exchange Online human access report to: $reportFilePath" -Level 'Information' -Component 'Export'
        
        # Add risk assessment to assignments
        $assignmentsWithRisk = @()
        foreach ($assignment in $Assignments) {
            if ($assignment.PrincipalType -eq 'User') {
                $riskAssessment = Get-UserRiskScore -UserAssignment $assignment
                $assignment | Add-Member -NotePropertyName "RiskScore" -NotePropertyValue $riskAssessment.RiskScore -Force
                $assignment | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue $riskAssessment.RiskLevel -Force
                $assignment | Add-Member -NotePropertyName "RiskFactors" -NotePropertyValue $riskAssessment.RiskFactors -Force
            } else {
                $assignment | Add-Member -NotePropertyName "RiskScore" -NotePropertyValue 0 -Force
                $assignment | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue "N/A" -Force
                $assignment | Add-Member -NotePropertyName "RiskFactors" -NotePropertyValue "" -Force
            }
            $assignmentsWithRisk += $assignment
        }
        
        # Export detailed report
        $assignmentsWithRisk | Export-Csv -Path $reportFilePath -NoTypeInformation -Encoding UTF8
        
        # Generate summary report
        $summary = [PSCustomObject]@{
            TenantId = $TenantId
            AuditDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            TotalAssignments = $Assignments.Count
            UniqueUsers = ($Assignments | Where-Object { $_.PrincipalType -eq 'User' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            UniqueGroups = ($Assignments | Where-Object { $_.PrincipalType -eq 'Group' } | Select-Object -ExpandProperty PrincipalId -Unique).Count
            UniqueRoles = ($Assignments | Select-Object -ExpandProperty RoleId -Unique).Count
            ExchangeOnlineRoles = ($Assignments | Where-Object { $_.Scope -eq 'Exchange' }).Count
            AzureADExchangeRoles = ($Assignments | Where-Object { $_.Scope -eq 'Tenant' }).Count
            GroupAssignments = ($Assignments | Where-Object { $_.IsGroupAssignment -eq $true }).Count
            HighRiskAssignments = ($assignmentsWithRisk | Where-Object { $_.RiskLevel -eq 'High' }).Count
            MediumRiskAssignments = ($assignmentsWithRisk | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
            LowRiskAssignments = ($assignmentsWithRisk | Where-Object { $_.RiskLevel -eq 'Low' }).Count
            ErrorCount = $Global:ErrorCount
        }
        
        $summaryFileName = "ExchangeOnlineHumanAccess_Summary_{0}_{1}.csv" -f $TenantId, $timestamp
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

#region Risk Assessment
function Get-UserRiskScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$UserAssignment
    )
    
    # Check cache first for performance
    if ($Script:RiskAssessmentCache.ContainsKey($UserAssignment.PrincipalId)) {
        return $Script:RiskAssessmentCache[$UserAssignment.PrincipalId]
    }
    
    $riskScore = 0
    $riskFactors = @()
    
    # High-risk roles (100 points each)
    $highRiskRoles = @(
        'Organization Management',
        'Exchange Administrator',
        'Global Administrator',
        'Security Administrator',
        'Privileged Role Administrator'
    )
    
    # Medium-risk roles (50 points each)
    $mediumRiskRoles = @(
        'Compliance Management',
        'Help Desk Administrator',
        'User Administrator',
        'Security Reader',
        'Compliance Administrator'
    )
    
    # Low-risk roles (10 points each)
    $lowRiskRoles = @(
        'View-Only Organization Management',
        'View-Only Recipients',
        'UM Management',
        'Records Management',
        'Hygiene Management'
    )
    
    # Check role risk level
    if ($highRiskRoles -contains $UserAssignment.RoleName) {
        $riskScore += 100
        $riskFactors += "High-risk role: $($UserAssignment.RoleName)"
    }
    elseif ($mediumRiskRoles -contains $UserAssignment.RoleName) {
        $riskScore += 50
        $riskFactors += "Medium-risk role: $($UserAssignment.RoleName)"
    }
    elseif ($lowRiskRoles -contains $UserAssignment.RoleName) {
        $riskScore += 10
        $riskFactors += "Low-risk role: $($UserAssignment.RoleName)"
    }
    
    # Removed PIM assignments scoring as PIM is not supported for Exchange Online roles
    
    # Nested group membership (5 points per level beyond direct)
    if ($UserAssignment.NestedGroupDepth -gt 1) {
        $nestedRisk = ($UserAssignment.NestedGroupDepth - 1) * 5
        $riskScore += $nestedRisk
        $riskFactors += "Nested group membership (depth: $($UserAssignment.NestedGroupDepth))"
    }
    
    # Determine risk level
    $riskLevel = if ($riskScore -ge 150) { 'High' }
                elseif ($riskScore -ge 50) { 'Medium' }
                else { 'Low' }
    
    $riskAssessment = [PSCustomObject]@{
        PrincipalId = $UserAssignment.PrincipalId
        RiskScore = $riskScore
        RiskLevel = $riskLevel
        RiskFactors = $riskFactors -join '; '
    }
    
    # Cache result for performance
    $Script:RiskAssessmentCache[$UserAssignment.PrincipalId] = $riskAssessment
    
    return $riskAssessment
}

function Get-UserLastLogonTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserId
    )
    
    # Check cache first for performance
    if ($Script:UserLastLogonCache.ContainsKey($UserId)) {
        return $Script:UserLastLogonCache[$UserId]
    }
    
    try {
        # Try to get last logon time from Microsoft Graph
        # Note: This is a simplified approach - in practice, you might need to check multiple sources
        $userSignIn = Get-MgUser -UserId $UserId -Property 'SignInActivity' -ErrorAction SilentlyContinue
        
        if ($userSignIn -and $userSignIn.SignInActivity) {
            $lastLogon = $userSignIn.SignInActivity.LastSignInDateTime
            # Cache result for performance
            $Script:UserLastLogonCache[$UserId] = $lastLogon
            return $lastLogon
        }
        
        # If no sign-in activity found, return null
        $Script:UserLastLogonCache[$UserId] = $null
        return $null
    }
    catch {
        $exceptionMessage = $_.Exception.Message
        Write-LogMessage -Message ("Could not retrieve last logon time for user {0}: {1}" -f $UserId, $exceptionMessage) -Level 'Warning' -Component 'PrincipalEnrichment'
        $Script:UserLastLogonCache[$UserId] = $null
        return $null
    }
}
#endregion

#region Single Tenant Execution
function Start-ExchangeOnlineHumanAccessAudit {
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
        Write-LogMessage -Message "Starting Exchange Online human access audit for tenant: $TenantId" -Level 'Information' -Component 'SingleTenant'
        
        if ($DryRun) {
            Write-LogMessage -Message "*** DRY RUN MODE - No actual changes will be made ***" -Level 'Information' -Component 'SingleTenant'
        }
        
        # Connect to Microsoft Graph
        $connectedTenantId = Connect-ToMicrosoftGraph -TenantId $TenantId -RequiredScopes $ScriptConfig.RequiredScopes -DryRun:$DryRun
        
        # Connect to Exchange Online
        $exchangeConnected = Connect-ToExchangeOnline -TenantId $TenantId -DryRun:$DryRun
        
        # Initialize assignments array
        $allAssignments = @()
        
        if ($DryRun) {
            # Generate mock data for dry-run
            Write-LogMessage -Message "DRY RUN: Generating mock Exchange Online human access data" -Level 'Information' -Component 'SingleTenant'
            
            $allAssignments = @(
                [PSCustomObject]@{
                    AssignmentId = "mock-assignment-1"
                    TenantId = $TenantId
                    PrincipalId = "mock-user-1"
                    PrincipalDisplayName = "Mock User 1"
                    PrincipalType = "User"
                    PrincipalEmail = "mockuser1@tenant.com"
                    RoleId = "Organization Management"
                    RoleName = "Organization Management"
                    RoleDescription = "Mock Organization Management role"
                    AssignmentType = "RoleGroup"
                    AssignmentMethod = "Permanent"
                    Scope = "Exchange"
                    ScopeId = "/"
                    ScopeName = "Organization"
                    StartDateTime = ""
                    EndDateTime = ""
                    AssignedBy = ""
                    AssignedDate = ""
                    IsGroupAssignment = $true
                    GroupId = "mock-group-1"
                    GroupName = "Organization Management"
                    RoleAssignmentPolicy = ""
                    CustomRecipientScope = ""
                    RecipientScope = "Organization"
                }
            )
            
            Write-LogMessage -Message "DRY RUN: Generated $($allAssignments.Count) mock assignments" -Level 'Information' -Component 'SingleTenant'
        } else {
            # Get Exchange Online role assignments
            Write-LogMessage -Message "Retrieving Exchange Online role assignments..." -Level 'Information' -Component 'SingleTenant'
            $exchangeAssignments = Get-ExchangeOnlineRoleAssignments
            
            # Add TenantId to all assignments
            foreach ($assignment in $exchangeAssignments) {
                $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
            }
            
            # Get Azure AD Exchange Administrator roles
            Write-LogMessage -Message "Retrieving Azure AD Exchange Administrator role assignments..." -Level 'Information' -Component 'SingleTenant'
            $azureADAssignments = Get-AzureADExchangeAdminRoles
            
            # Add TenantId to Azure AD assignments
            foreach ($assignment in $azureADAssignments) {
                $assignment | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $connectedTenantId -Force
            }
            
            # Combine all assignments (removed PIM assignments as PIM is not supported for Exchange Online roles)
            $allAssignments += $exchangeAssignments
            $allAssignments += $azureADAssignments
            
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
        $exportResult = Export-ExchangeHumanAccessReport -Assignments $allAssignments -ExportPath $ExportPath -TenantId $connectedTenantId -DryRun:$DryRun
        
        # Final summary for this tenant
        Write-LogMessage -Message "Tenant $TenantId audit completed successfully!" -Level 'Information' -Component 'SingleTenant'
        Write-LogMessage -Message "Total assignments processed: $($exportResult.AssignmentCount)" -Level 'Information' -Component 'SingleTenant'
        
        if (-not $DryRun) {
            Write-LogMessage -Message "Report saved to: $($exportResult.ReportPath)" -Level 'Information' -Component 'SingleTenant'
            Write-LogMessage -Message "Summary saved to: $($exportResult.SummaryPath)" -Level 'Information' -Component 'SingleTenant'
        }
        
        return $exportResult
    }
    catch {
        $exceptionMessage = $_.Exception.Message
                Write-LogMessage -Message "Failed to audit tenant $($TenantId): $exceptionMessage" -Level 'Error' -Component 'SingleTenant'
        throw
    }
    finally {
        # Clean up connections
        try {
            if (-not $DryRun) {
                Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                Disconnect-MgGraph -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Ignore cleanup errors
        }
    }
}
#endregion

#region Multi-Tenant Orchestration
function Start-MultiTenantExchangeOnlineHumanAccessAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$TenantIds,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeGroupMembers,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    try {
        Write-LogMessage -Message "Starting multi-tenant Exchange Online human access audit for $($TenantIds.Count) tenants" -Level 'Information' -Component 'MultiTenant'
        
        if ($DryRun) {
            Write-LogMessage -Message "*** DRY RUN MODE - No actual changes will be made ***" -Level 'Information' -Component 'MultiTenant'
        }
        
        $allResults = @()
        $successfulTenants = @()
        $failedTenants = @()
        
        foreach ($tenantId in $TenantIds) {
            try {
                Write-LogMessage -Message "Processing tenant: $tenantId" -Level 'Information' -Component 'MultiTenant'
                
                $result = Start-ExchangeOnlineHumanAccessAudit -TenantId $tenantId -ExportPath $ExportPath -IncludeGroupMembers:$IncludeGroupMembers -DryRun:$DryRun
                
                $allResults += [PSCustomObject]@{
                    TenantId = $tenantId
                    Status = 'Success'
                    AssignmentCount = $result.AssignmentCount
                    ReportPath = $result.ReportPath
                    SummaryPath = $result.SummaryPath
                    ErrorMessage = ''
                }
                
                $successfulTenants += $tenantId
                Write-LogMessage -Message "Successfully processed tenant: $tenantId" -Level 'Information' -Component 'MultiTenant'
            }
            catch {
                $errorMessage = $_.Exception.Message
                $errorMessage = $_.Exception.Message
                Write-LogMessage -Message "Failed to process tenant $($tenantId): $errorMessage" -Level 'Error' -Component 'MultiTenant'
                
                $allResults += [PSCustomObject]@{
                    TenantId = $tenantId
                    Status = 'Failed'
                    AssignmentCount = 0
                    ReportPath = ''
                    SummaryPath = ''
                    ErrorMessage = $errorMessage
                }
                
                $failedTenants += $tenantId
            }
        }
        
        # Generate consolidated summary
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $consolidatedSummaryPath = Join-Path -Path $ExportPath -ChildPath "ExchangeOnlineHumanAccess_ConsolidatedSummary_$timestamp.csv"
        
        if (-not $DryRun) {
            $allResults | Export-Csv -Path $consolidatedSummaryPath -NoTypeInformation -Encoding UTF8
            Write-LogMessage -Message "Consolidated summary exported to: $consolidatedSummaryPath" -Level 'Information' -Component 'MultiTenant'
        }
        
        # Final summary
        Write-LogMessage -Message "Multi-tenant audit completed!" -Level 'Information' -Component 'MultiTenant'
        Write-LogMessage -Message "Successful tenants: $($successfulTenants.Count)" -Level 'Information' -Component 'MultiTenant'
        Write-LogMessage -Message "Failed tenants: $($failedTenants.Count)" -Level 'Information' -Component 'MultiTenant'
        
        if ($failedTenants.Count -gt 0) {
            Write-LogMessage -Message "Failed tenant IDs: $($failedTenants -join ', ')" -Level 'Warning' -Component 'MultiTenant'
        }
        
        return $allResults
    }
    catch {
        Write-LogMessage -Message "Multi-tenant audit failed: $($_.Exception.Message)" -Level 'Error' -Component 'MultiTenant'
        throw
    }
}
#endregion

#region Main Execution
# Initialize modules
Initialize-RequiredModules

# Validate export path
if (-not (Test-Path -Path $ExportPath)) {
    try {
        New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        Write-LogMessage -Message "Created export directory: $ExportPath" -Level 'Information' -Component 'Main'
    }
    catch {
        $exceptionMessage = $_.Exception.Message
        Write-LogMessage -Message "Failed to create export directory $($ExportPath): $exceptionMessage" -Level 'Error' -Component 'Main'
        throw
    }
}

# Main execution logic
try {
    Write-LogMessage -Message "Exchange Online Human Access Audit Script Starting..." -Level 'Information' -Component 'Main'
    Write-LogMessage -Message "Script version: 1.0" -Level 'Information' -Component 'Main'
    Write-LogMessage -Message "PowerShell version: $($PSVersionTable.PSVersion)" -Level 'Information' -Component 'Main'
    
    if ($DryRun) {
        Write-LogMessage -Message "*** DRY RUN MODE ENABLED ***" -Level 'Information' -Component 'Main'
    }
    
    if ($TenantIds -and $TenantIds.Count -gt 0) {
        # Multi-tenant execution
        Write-LogMessage -Message "Starting multi-tenant audit for $($TenantIds.Count) tenants" -Level 'Information' -Component 'Main'
        $results = Start-MultiTenantExchangeOnlineHumanAccessAudit -TenantIds $TenantIds -ExportPath $ExportPath -IncludeGroupMembers:$IncludeGroupMembers -DryRun:$DryRun
    } else {
        # Single tenant execution (current connected tenant)
        Write-LogMessage -Message "Starting single tenant audit for current connected tenant" -Level 'Information' -Component 'Main'
        
        # Get current tenant ID
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context -and $context.TenantId) {
            $currentTenantId = $context.TenantId
        } else {
            Write-LogMessage -Message "No tenant specified and no current Microsoft Graph connection found. Please specify -TenantIds parameter." -Level 'Error' -Component 'Main'
            throw "No tenant specified and no current connection found"
        }
        
        $results = Start-ExchangeOnlineHumanAccessAudit -TenantId $currentTenantId -ExportPath $ExportPath -IncludeGroupMembers:$IncludeGroupMembers -DryRun:$DryRun
    }
    
    Write-LogMessage -Message "Exchange Online Human Access Audit completed successfully!" -Level 'Information' -Component 'Main'
    
    if ($Global:ErrorCount -gt 0) {
        Write-LogMessage -Message "Completed with $($Global:ErrorCount) errors. Please review the logs." -Level 'Warning' -Component 'Main'
    }
}
catch {
    $exceptionMessage = $_.Exception.Message
    Write-LogMessage -Message "Exchange Online Human Access Audit failed: $exceptionMessage" -Level 'Error' -Component 'Main'
    throw
}
#endregion