# Enhanced Exchange Online Role Assignments Script
# Connects to Exchange Online and retrieves all role assignments with enhanced details

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
        
        # Use PowerShell 5.1 compatible connection method
        if ($TenantId) {
            Connect-ExchangeOnline -Organization $TenantId -ShowBanner:$false -ErrorAction Stop
        } else {
            # For PowerShell 5.1, use the most compatible connection method
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
        
        Write-Host "Successfully connected to Exchange Online" -ForegroundColor Green
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
            Write-Warning "2. Or manually connect using: Connect-ExchangeOnline -ShowBanner:`$false"
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
                
                switch ($assignment.RoleAssigneeType) {
                    "User" {
                        try {
                            $assigneeDetails = Get-User -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                            if ($assigneeDetails) {
                                $assigneeEmail = if ($assigneeDetails.PrimarySmtpAddress) { $assigneeDetails.PrimarySmtpAddress } else { "N/A" }
                                $assigneeDisplayName = if ($assigneeDetails.DisplayName) { $assigneeDetails.DisplayName } else { $assignment.RoleAssigneeName }
                            }
                        } catch {
                            Write-Warning "Could not get user details for $($assignment.RoleAssigneeName)"
                        }
                    }
                    "Group" {
                        try {
                            $assigneeDetails = Get-Group -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                            if ($assigneeDetails) {
                                $assigneeEmail = if ($assigneeDetails.PrimarySmtpAddress) { $assigneeDetails.PrimarySmtpAddress } else { "N/A" }
                                $assigneeDisplayName = if ($assigneeDetails.DisplayName) { $assigneeDetails.DisplayName } else { $assignment.RoleAssigneeName }
                            }
                        } catch {
                            Write-Warning "Could not get group details for $($assignment.RoleAssigneeName)"
                        }
                    }
                    "RoleGroup" {
                        try {
                            $assigneeDetails = Get-RoleGroup -Identity $assignment.RoleAssigneeName -ErrorAction SilentlyContinue
                            if ($assigneeDetails) {
                                $assigneeEmail = if ($assigneeDetails.WindowsEmailAddress) { $assigneeDetails.WindowsEmailAddress } else { "N/A" }
                                $assigneeDisplayName = if ($assigneeDetails.DisplayName) { $assigneeDetails.DisplayName } else { $assignment.RoleAssigneeName }
                                
                                # Get member details if requested
                                if ($IncludeMemberDetails) {
                                    $memberDetails = Get-RoleGroupMembers -RoleGroupName $assignment.RoleAssigneeName
                                }
                            }
                        } catch {
                            Write-Warning "Could not get role group details for $($assignment.RoleAssigneeName)"
                        }
                    }
                    "PartnerLinkedRoleGroup" {
                        # Special handling for partner linked role groups
                        $assigneeEmail = "N/A"
                        $assigneeDisplayName = $assignment.RoleAssigneeName
                    }
                    default {
                        # For any other assignee type
                        $assigneeEmail = "N/A"
                        $assigneeDisplayName = $assignment.RoleAssigneeName
                    }
                }
                
                # Create detailed assignment object with better formatting
                $detailedAssignment = [PSCustomObject]@{
                    AssignmentId = if ($assignment.Id) { $assignment.Id } else { "N/A" }
                    AssignmentName = if ($assignment.Name) { $assignment.Name } else { "N/A" }
                    RoleName = if ($assignment.Role) { $assignment.Role } else { "N/A" }
                    RoleDescription = if ($roleDetails -and $roleDetails.Description) { 
                        # Clean up the description by removing extra whitespace and newlines
                        ($roleDetails.Description -replace '\s+', ' ').Trim() 
                    } else { "N/A" }
                    RoleType = if ($roleDetails -and $roleDetails.RoleType) { $roleDetails.RoleType } else { "N/A" }
                    AssigneeId = if ($assignment.RoleAssigneeId) { $assignment.RoleAssigneeId } else { "N/A" }
                    AssigneeName = $assigneeDisplayName
                    AssigneeType = if ($assignment.RoleAssigneeType) { $assignment.RoleAssigneeType } else { "N/A" }
                    AssigneeEmail = $assigneeEmail
                    AssignmentMethod = if ($assignment.AssignmentMethod) { $assignment.AssignmentMethod } else { "N/A" }
                    RecipientWriteScope = if ($assignment.RecipientWriteScope) { $assignment.RecipientWriteScope } else { "N/A" }
                    CustomRecipientWriteScope = if ($assignment.CustomRecipientWriteScope) { $assignment.CustomRecipientWriteScope } else { "" }
                    ConfigWriteScope = if ($assignment.ConfigWriteScope) { $assignment.ConfigWriteScope } else { "N/A" }
                    CustomConfigWriteScope = if ($assignment.CustomConfigWriteScope) { $assignment.CustomConfigWriteScope } else { "" }
                    WhenCreated = if ($assignment.WhenCreated) { $assignment.WhenCreated.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                    WhenChanged = if ($assignment.WhenChanged) { $assignment.WhenChanged.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
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
        $filename = "ExchangeOnline_RoleAssignments_Enhanced_$timestamp.csv"
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
    Write-Host "Enhanced Exchange Online Role Assignments Script" -ForegroundColor Cyan
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