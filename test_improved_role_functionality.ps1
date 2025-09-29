# Test script for improved Exchange Online role functionality
Write-Host "Testing improved Exchange Online role assignment retrieval..." -ForegroundColor Yellow

try {
    # Import Exchange Online module
    Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
    Write-Host "Exchange Online module imported successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Exchange Online module: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "Testing connection to Exchange Online..." -ForegroundColor Cyan
    
    # Check for existing connection first
    $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($existingConnection) {
        Write-Host "Using existing Exchange Online connection" -ForegroundColor Green
    } else {
        # Connect if not already connected
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Host "Successfully connected to Exchange Online!" -ForegroundColor Green
    }
    
    # Test retrieving a few role assignments
    Write-Host "Testing role assignment retrieval..." -ForegroundColor Cyan
    $roleAssignments = Get-ManagementRoleAssignment -ResultSize 5 -ErrorAction Stop
    Write-Host "Retrieved $($roleAssignments.Count) sample role assignments" -ForegroundColor Green
    
    # Test retrieving details for different assignee types
    foreach ($assignment in $roleAssignments) {
        Write-Host "Testing assignment: $($assignment.Name)" -ForegroundColor Gray
        
        # Get role details
        $roleDetails = Get-ManagementRole -Identity $assignment.Role -ErrorAction SilentlyContinue
        Write-Host "  Role: $($assignment.Role)" -ForegroundColor Gray
        
        # Test different methods based on assignee type
        switch ($assignment.RoleAssigneeType) {
            "User" {
                Write-Host "  Assignee Type: User ($($assignment.RoleAssigneeName))" -ForegroundColor Gray
                try {
                    $userDetails = Get-User -Identity $assignment.RoleAssigneeName -ErrorAction Stop
                    Write-Host "    User Email: $($userDetails.PrimarySmtpAddress)" -ForegroundColor Green
                    Write-Host "    User Display Name: $($userDetails.DisplayName)" -ForegroundColor Green
                } catch {
                    Write-Host "    Failed to get user details: $($_.Exception.Message)" -ForegroundColor Red
                    try {
                        $recipientDetails = Get-Recipient -Identity $assignment.RoleAssigneeName -ErrorAction Stop
                        Write-Host "    Recipient Email: $($recipientDetails.PrimarySmtpAddress)" -ForegroundColor Yellow
                    } catch {
                        Write-Host "    Failed to get recipient details either: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
            "Group" {
                Write-Host "  Assignee Type: Group ($($assignment.RoleAssigneeName))" -ForegroundColor Gray
                try {
                    $groupDetails = Get-Group -Identity $assignment.RoleAssigneeName -ErrorAction Stop
                    Write-Host "    Group Email: $($groupDetails.PrimarySmtpAddress)" -ForegroundColor Green
                } catch {
                    Write-Host "    Failed to get group details: $($_.Exception.Message)" -ForegroundColor Red
                    try {
                        $recipientDetails = Get-Recipient -Identity $assignment.RoleAssigneeName -ErrorAction Stop
                        Write-Host "    Recipient Email: $($recipientDetails.PrimarySmtpAddress)" -ForegroundColor Yellow
                    } catch {
                        Write-Host "    Failed to get recipient details either: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
            "RoleGroup" {
                Write-Host "  Assignee Type: RoleGroup ($($assignment.RoleAssigneeName))" -ForegroundColor Gray
                try {
                    $roleGroupDetails = Get-RoleGroup -Identity $assignment.RoleAssigneeName -ErrorAction Stop
                    Write-Host "    Role Group Email: $($roleGroupDetails.WindowsEmailAddress)" -ForegroundColor Green
                } catch {
                    Write-Host "    Failed to get role group details: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            default {
                Write-Host "  Assignee Type: $($assignment.RoleAssigneeType) ($($assignment.RoleAssigneeName))" -ForegroundColor Gray
                try {
                    $recipientDetails = Get-Recipient -Identity $assignment.RoleAssigneeName -ErrorAction Stop
                    Write-Host "    Recipient Email: $($recipientDetails.PrimarySmtpAddress)" -ForegroundColor Green
                } catch {
                    Write-Host "    Failed to get recipient details: $($_.Exception.Message)" -ForegroundColor Red
                    try {
                        $userDetails = Get-User -Identity $assignment.RoleAssigneeName -ErrorAction Stop
                        Write-Host "    User Email: $($userDetails.PrimarySmtpAddress)" -ForegroundColor Yellow
                    } catch {
                        Write-Host "    Failed to get user details either: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
    }
    
    Write-Host "`nTesting complete. If you saw email addresses above, the improved script should work correctly." -ForegroundColor Cyan
    
    # Disconnect
    # Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    # Write-Host "Disconnected from Exchange Online" -ForegroundColor Gray
    
} catch {
    Write-Error "Test failed: $($_.Exception.Message)"
    exit 1
}

Write-Host "Test completed successfully!" -ForegroundColor Green