# Improved Exchange Online Role Assignments Script
# Connects to Exchange Online and retrieves all role assignments with comprehensive user/group details

param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMemberDetails
)

#region Functions
function Connect-ToExchangeOnline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-Host "DRY RUN: Would connect to Exchange Online" -ForegroundColor Yellow
        return $true
    }
    
    try {
        Write-Host "Checking for existing Exchange Online connection..." -ForegroundColor Yellow
        
        # Check if already connected using the proper cmdlet
        $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($existingConnection) {
            Write-Host "Using existing Exchange Online connection" -ForegroundColor Green
            Write-Host "Connection state: $($existingConnection.State)" -ForegroundColor Gray
            return $true
        }
        
        Write-Host "No existing connection found. Connecting to Exchange Online..." -ForegroundColor Yellow
        
        # Disconnect any existing session
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore disconnect errors
        }
        
        # Check PowerShell version for appropriate connection method
        $psVersion = $PSVersionTable.PSVersion
        Write-Host "PowerShell Version: $psVersion" -ForegroundColor Yellow
        
        # PowerShell 5.1 specific workarounds
        if ($psVersion.Major -eq 5) {
            Write-Host "Applying PowerShell 5.1 specific workarounds..." -ForegroundColor Yellow
            
            # Workaround 1: Set specific .NET culture settings
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
            [System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture
            
            # Workaround 2: Use DisableWAM parameter to avoid window handle issues
            $connectParams = @{
                ShowBanner = $false
                DisableWAM = $true
                ErrorAction = 'Stop'
            }
            
            if ($TenantId) {
                $connectParams.Add('Organization', $TenantId)
            }
            
            Write-Host "Attempting connection with DisableWAM parameter..." -ForegroundColor Gray
            Connect-ExchangeOnline @connectParams
            Write-Host "Successfully connected using PowerShell 5.1 workaround!" -ForegroundColor Green
        }
        else {
            # For PowerShell 7+, use standard methods
            if ($TenantId) {
                Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false -ErrorAction Stop
            } else {
                Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            }
            Write-Host "Successfully connected to Exchange Online" -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        # Provide specific guidance for common connection issues
        $errorMessage = $_.Exception.Message
        if ($errorMessage -like "*window handle*") {
            Write-Warning "Connection failed due to a known PowerShell 5.1 compatibility issue."
            Write-Warning "This error occurs when Exchange Online tries to use interactive authentication."
            Write-Warning ""
            Write-Warning "SOLUTIONS:"
            Write-Warning "1. Run the PreAuth-ExchangeOnline.ps1 script first to establish a connection"
            Write-Warning "2. Or manually connect using: Connect-ExchangeOnline -ShowBanner:`$false -DisableWAM `$true"
            Write-Warning "3. Then run this script again"
            Write-Warning ""
            Write-Warning "This approach avoids the authentication prompt that causes the window handle error."
        }
        Write-Error "Failed to connect to Exchange Online: $errorMessage"
        throw
    }
}

function Get-RoleGroupMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RoleGroupName
    )
    
    try {
        $members = Get-RoleGroupMember -Identity $RoleGroupName -ErrorAction SilentlyContinue
        if ($members) {
            return ($members | ForEach-Object { $_.Name }) -join "; "
        } else {
            return "No members found"
        }
    }
    catch {
        return "Error retrieving members: $($_.Exception.Message)"
    }
}

function Get-DetailedRoleAssignments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeMemberDetails
    )
    
    if ($DryRun) {
        Write-Host "DRY RUN: Would retrieve Exchange Online role assignments" -ForegroundColor Yellow
        
        # Return mock data for dry run
        $mockAssignments = @(
            [PSCustomObject]@{
                AssignmentId = "MOCK-ASSIGNMENT-001"
                AssignmentName = "Mock Assignment 1"
                RoleName = "Organization Management"
                RoleDescription = "Mock role for managing organization"
                RoleType = "Role"
                AssigneeId = "MOCK-USER-001"
                AssigneeName = "Mock User 1"
                AssigneeType = "User"
                AssigneeEmail = "mockuser1@tenant.com"
                AssignmentMethod = "Direct"
                RecipientWriteScope = "Organization"
                CustomRecipientWriteScope = ""
                ConfigWriteScope = "Organization"
                CustomConfigWriteScope = ""
                WhenCreated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                WhenChanged = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                MemberDetails = "N/A"
            },
            [PSCustomObject]@{
                AssignmentId = "MOCK-ASSIGNMENT-002"
                AssignmentName = "Mock Assignment 2"
                RoleName = "Records Management"
                RoleDescription = "Mock role for managing records"
                RoleType = "Role"
                AssigneeId = "MOCK-GROUP-001"
                AssigneeName = "Mock Group 1"
                AssigneeType = "Group"
                AssigneeEmail = "mockgroup1@tenant.com"
                AssignmentMethod = "Group"
                RecipientWriteScope = "Organization"
                CustomRecipientWriteScope = ""
                ConfigWriteScope = "Organization"
                CustomConfigWriteScope = ""
                WhenCreated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                WhenChanged = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                MemberDetails = "Mock User 1; Mock User 2"
            }
        )
        
        Write-Host "DRY RUN: Returning mock data with 2 assignments" -ForegroundColor Yellow
        return $mockAssignments
    }
    
    try {
        Write-Host "Retrieving Exchange Online role assignments..." -ForegroundColor Green
        
        # Get all management role assignments
        $roleAssignments = Get-ManagementRoleAssignment -ErrorAction Stop
        
        $detailedAssignments = @()
        
        $totalAssignments = $roleAssignments.Count
        $currentAssignment = 0
        
        foreach ($assignment in $roleAssignments) {
            $currentAssignment++
            Write-Progress -Activity "Processing Role Assignments" -Status "Processing assignment $currentAssignment of $totalAssignments" -PercentComplete (($currentAssignment / $totalAssignments) * 100)
            
            try {
                # Get additional details about the role
                $roleDetails = Get-ManagementRole -Identity $assignment.Role -ErrorAction SilentlyContinue
                
                # Get details about the assignee with better error handling
                $assigneeDetails = $null
                $assigneeEmail = "N/A"
                $assigneeDisplayName = $assignment.RoleAssigneeName
                $memberDetails = "N/A"
                $assigneeUPN = "N/A"
                
                switch ($assignment.RoleAssigneeType) {
                    "User" {
                        try {
                            # Try multiple approaches to get user details
                            $assigneeDetails = Get-User -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                            
                            if ($assigneeDetails) {
                                $assigneeEmail = if ($assigneeDetails.PrimarySmtpAddress) { $assigneeDetails.PrimarySmtpAddress.ToString().Trim() } else { "N/A" }
                                $assigneeDisplayName = if ($assigneeDetails.DisplayName) { $assigneeDetails.DisplayName.ToString().Trim() } else { $assignment.RoleAssigneeName }
                                $assigneeUPN = if ($assigneeDetails.UserPrincipalName) { $assigneeDetails.UserPrincipalName.ToString().Trim() } else { "N/A" }
                            } else {
                                # Try Get-Recipient as fallback
                                $recipientDetails = Get-Recipient -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                                if ($recipientDetails) {
                                    $assigneeEmail = if ($recipientDetails.PrimarySmtpAddress) { $recipientDetails.PrimarySmtpAddress.ToString().Trim() } else { "N/A" }
                                    $assigneeDisplayName = if ($recipientDetails.DisplayName) { $recipientDetails.DisplayName.ToString().Trim() } else { $assignment.RoleAssigneeName }
                                }
                            }
                        } catch {
                            Write-Warning "Could not get user details for $($assignment.RoleAssigneeName): $($_.Exception.Message)"
                        }
                    }
                    "Group" {
                        try {
                            # Try to get group details
                            $assigneeDetails = Get-Group -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                            
                            if ($assigneeDetails) {
                                $assigneeEmail = if ($assigneeDetails.PrimarySmtpAddress) { $assigneeDetails.PrimarySmtpAddress.ToString().Trim() } else { "N/A" }
                                $assigneeDisplayName = if ($assigneeDetails.DisplayName) { $assigneeDetails.DisplayName.ToString().Trim() } else { $assignment.RoleAssigneeName }
                            } else {
                                # Try Get-Recipient as fallback
                                $recipientDetails = Get-Recipient -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                                if ($recipientDetails) {
                                    $assigneeEmail = if ($recipientDetails.PrimarySmtpAddress) { $recipientDetails.PrimarySmtpAddress.ToString().Trim() } else { "N/A" }
                                    $assigneeDisplayName = if ($recipientDetails.DisplayName) { $recipientDetails.DisplayName.ToString().Trim() } else { $assignment.RoleAssigneeName }
                                }
                            }
                        } catch {
                            Write-Warning "Could not get group details for $($assignment.RoleAssigneeName): $($_.Exception.Message)"
                        }
                    }
                    "RoleGroup" {
                        try {
                            # Try to get role group details
                            $assigneeDetails = Get-RoleGroup -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                            
                            if ($assigneeDetails) {
                                $assigneeEmail = if ($assigneeDetails.WindowsEmailAddress) { $assigneeDetails.WindowsEmailAddress.ToString().Trim() } else { "N/A" }
                                $assigneeDisplayName = if ($assigneeDetails.DisplayName) { $assigneeDetails.DisplayName.ToString().Trim() } else { $assignment.RoleAssigneeName }
                                
                                # Get member details if requested
                                if ($IncludeMemberDetails) {
                                    $memberDetails = Get-RoleGroupMembers -RoleGroupName $assignment.RoleAssigneeName
                                }
                            }
                        } catch {
                            Write-Warning "Could not get role group details for $($assignment.RoleAssigneeName): $($_.Exception.Message)"
                        }
                    }
                    "PartnerLinkedRoleGroup" {
                        # Special handling for partner linked role groups
                        $assigneeEmail = "N/A"
                        $assigneeDisplayName = $assignment.RoleAssigneeName
                        $assigneeUPN = "N/A"
                    }
                    default {
                        # For any other assignee type, try generic approaches
                        try {
                            # Try Get-Recipient first
                            $recipientDetails = Get-Recipient -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                            if ($recipientDetails) {
                                $assigneeEmail = if ($recipientDetails.PrimarySmtpAddress) { $recipientDetails.PrimarySmtpAddress.ToString().Trim() } else { "N/A" }
                                $assigneeDisplayName = if ($recipientDetails.DisplayName) { $recipientDetails.DisplayName.ToString().Trim() } else { $assignment.RoleAssigneeName }
                                $assigneeUPN = if ($recipientDetails.PrimarySmtpAddress) { $recipientDetails.PrimarySmtpAddress.ToString().Trim() } else { "N/A" }
                            } else {
                                # Try Get-User as fallback
                                $userDetails = Get-User -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                                if ($userDetails) {
                                    $assigneeEmail = if ($userDetails.PrimarySmtpAddress) { $userDetails.PrimarySmtpAddress.ToString().Trim() } else { "N/A" }
                                    $assigneeDisplayName = if ($userDetails.DisplayName) { $userDetails.DisplayName.ToString().Trim() } else { $assignment.RoleAssigneeName }
                                    $assigneeUPN = if ($userDetails.UserPrincipalName) { $userDetails.UserPrincipalName.ToString().Trim() } else { "N/A" }
                                }
                            }
                        } catch {
                            Write-Warning "Could not get details for $($assignment.RoleAssigneeName) (type: $($assignment.RoleAssigneeType)): $($_.Exception.Message)"
                        }
                        
                        # If all else fails, use the assignment name
                        if ($assigneeEmail -eq "N/A") {
                            $assigneeEmail = "N/A"
                        }
                        if ($assigneeDisplayName -eq $assignment.RoleAssigneeName) {
                            $assigneeDisplayName = $assignment.RoleAssigneeName
                        }
                        if ($assigneeUPN -eq "N/A") {
                            $assigneeUPN = "N/A"
                        }
                    }
                }
                
                # Clean up values to ensure they're strings and not null
                $assignmentId = if ($assignment.Id) { $assignment.Id.ToString().Trim() } else { "N/A" }
                $assignmentName = if ($assignment.Name) { $assignment.Name.ToString().Trim() } else { "N/A" }
                $roleName = if ($assignment.Role) { $assignment.Role.ToString().Trim() } else { "N/A" }
                $roleDescription = if ($roleDetails -and $roleDetails.Description) { 
                    # Clean up the description by removing extra whitespace and newlines
                    ($roleDetails.Description.ToString() -replace '\s+', ' ').Trim() 
                } else { "N/A" }
                $roleType = if ($roleDetails -and $roleDetails.RoleType) { $roleDetails.RoleType.ToString().Trim() } else { "N/A" }
                $assigneeId = if ($assignment.RoleAssigneeId) { $assignment.RoleAssigneeId.ToString().Trim() } else { "N/A" }
                $assigneeType = if ($assignment.RoleAssigneeType) { $assignment.RoleAssigneeType.ToString().Trim() } else { "N/A" }
                $assignmentMethod = if ($assignment.AssignmentMethod) { $assignment.AssignmentMethod.ToString().Trim() } else { "N/A" }
                $recipientWriteScope = if ($assignment.RecipientWriteScope) { $assignment.RecipientWriteScope.ToString().Trim() } else { "N/A" }
                $customRecipientWriteScope = if ($assignment.CustomRecipientWriteScope) { $assignment.CustomRecipientWriteScope.ToString().Trim() } else { "" }
                $configWriteScope = if ($assignment.ConfigWriteScope) { $assignment.ConfigWriteScope.ToString().Trim() } else { "N/A" }
                $customConfigWriteScope = if ($assignment.CustomConfigWriteScope) { $assignment.CustomConfigWriteScope.ToString().Trim() } else { "" }
                $whenCreated = if ($assignment.WhenCreated) { $assignment.WhenCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                $whenChanged = if ($assignment.WhenChanged) { $assignment.WhenChanged.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                
                # Create detailed assignment object with better formatting
                $detailedAssignment = [PSCustomObject]@{
                    AssignmentId = $assignmentId
                    AssignmentName = $assignmentName
                    RoleName = $roleName
                    RoleDescription = $roleDescription
                    RoleType = $roleType
                    AssigneeId = $assigneeId
                    AssigneeName = $assigneeDisplayName
                    AssigneeType = $assigneeType
                    AssigneeEmail = $assigneeEmail
                    AssigneeUPN = $assigneeUPN
                    AssignmentMethod = $assignmentMethod
                    RecipientWriteScope = $recipientWriteScope
                    CustomRecipientWriteScope = $customRecipientWriteScope
                    ConfigWriteScope = $configWriteScope
                    CustomConfigWriteScope = $customConfigWriteScope
                    WhenCreated = $whenCreated
                    WhenChanged = $whenChanged
                    MemberDetails = $memberDetails
                }
                
                $detailedAssignments += $detailedAssignment
            }
            catch {
                Write-Warning "Error processing assignment $($assignment.Id): $($_.Exception.Message)"
            }
        }
        
        Write-Progress -Activity "Processing Role Assignments" -Completed
        Write-Host "Retrieved $($detailedAssignments.Count) role assignments" -ForegroundColor Green
        return $detailedAssignments
    }
    catch {
        Write-Error "Failed to retrieve role assignments: $($_.Exception.Message)"
        throw
    }
}

function Export-AssignmentsToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Assignments,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-Host "DRY RUN: Would export $($Assignments.Count) assignments to CSV" -ForegroundColor Yellow
        Write-Host "DRY RUN: Export path would be: $ExportPath" -ForegroundColor Yellow
        return "DRY_RUN_ExportPath\ExchangeOnline_RoleAssignments_TIMESTAMP.csv"
    }
    
    try {
        # Ensure export path exists
        if (-not (Test-Path -Path $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "ExchangeOnline_RoleAssignments_Improved_$timestamp.csv"
        $filepath = Join-Path -Path $ExportPath -ChildPath $filename
        
        # Export to CSV with better encoding
        $Assignments | Export-Csv -Path $filepath -NoTypeInformation -Encoding UTF8
        
        Write-Host "Assignments exported to: $filepath" -ForegroundColor Green
        return $filepath
    }
    catch {
        Write-Error "Failed to export assignments: $($_.Exception.Message)"
        throw
    }
}
#endregion

#region Main Execution
try {
    Write-Host "Improved Exchange Online Role Assignments Script" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    
    if ($IncludeMemberDetails) {
        Write-Host "Member details will be included for Role Groups (this may take longer)" -ForegroundColor Yellow
    }
    
    if ($DryRun) {
        Write-Host "*** DRY RUN MODE ENABLED ***" -ForegroundColor Yellow
        Write-Host "No actual connections or changes will be made" -ForegroundColor Yellow
        Write-Host "=========================================" -ForegroundColor Yellow
    }
    
    # Connect to Exchange Online
    Connect-ToExchangeOnline -TenantId $TenantId -DryRun:$DryRun
    
    # Get detailed role assignments
    $assignments = Get-DetailedRoleAssignments -DryRun:$DryRun -IncludeMemberDetails:$IncludeMemberDetails
    
    # Display summary
    Write-Host "`nSummary:" -ForegroundColor Yellow
    Write-Host "Total Role Assignments: $($assignments.Count)" -ForegroundColor Yellow
    
    # Group by assignee type for better summary
    $assignments | Group-Object AssigneeType | ForEach-Object {
        Write-Host "$($_.Name): $($_.Count)" -ForegroundColor Gray
    }
    
    # Export to CSV
    if ($assignments.Count -gt 0) {
        $exportPath = Export-AssignmentsToCsv -Assignments $assignments -ExportPath $ExportPath -DryRun:$DryRun
        if (-not $DryRun) {
            Write-Host "`nDetailed report exported to: $exportPath" -ForegroundColor Green
        } else {
            Write-Host "`nDRY RUN: Report would be exported to: $exportPath" -ForegroundColor Yellow
        }
    }
    
    # Display sample of assignments with better formatting
    Write-Host "`nSample of Role Assignments:" -ForegroundColor Yellow
    $assignments | Select-Object -First 10 | Format-Table -Property @{Name="Assignee Name";Expression={$_.AssigneeName};Width=30}, @{Name="Assignee Type";Expression={$_.AssigneeType};Width=15}, @{Name="Role Name";Expression={$_.RoleName};Width=30}, @{Name="Assignee Email";Expression={$_.AssigneeEmail};Width=30} -AutoSize
    
    Write-Host "`nScript completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    exit 1
}
finally {
    # Clean up connection
    try {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore disconnect errors
    }
}
#endregion