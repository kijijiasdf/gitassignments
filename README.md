# Exchange Online Role Assignments Script

This is a simplified PowerShell script that connects to Exchange Online and retrieves all role assignments with detailed information.

## Features

- Connects to Exchange Online (with or without specifying a Tenant ID)
- Retrieves all management role assignments
- Enriches assignments with detailed information about roles and assignees
- Exports results to a CSV file with timestamp
- Shows a summary and sample of the retrieved assignments
- **Dry-run mode** for testing without making actual connections

## Prerequisites

1. PowerShell 5.1 or later
2. Exchange Online PowerShell module (ExchangeOnlineManagement)
3. Appropriate permissions to read role assignments in Exchange Online

## Installation

Install the required PowerShell module:

```powershell
Install-Module -Name ExchangeOnlineManagement -Force
```

## Usage

### Method 1: Two-Step Process (Recommended for PowerShell 5.1)

1. First, run the pre-authentication script to establish a connection:
```powershell
.\PreAuth-ExchangeOnline.ps1
```

2. Then run the main script:
```powershell
.\ExchangeOnline-RoleAssignments.ps1
```

### Method 2: Direct Execution

```powershell
.\ExchangeOnline-RoleAssignments.ps1
```

### With Specific Tenant ID

```powershell
.\ExchangeOnline-RoleAssignments.ps1 -TenantId "your-tenant-id-guid"
```

### With Custom Export Path

```powershell
.\ExchangeOnline-RoleAssignments.ps1 -ExportPath "C:\Reports"
```

### Dry Run Mode (Simulation)

```powershell
.\ExchangeOnline-RoleAssignments.ps1 -DryRun
```

### With All Parameters

```powershell
.\ExchangeOnline-RoleAssignments.ps1 -TenantId "your-tenant-id-guid" -ExportPath "C:\Reports" -DryRun
```

## Troubleshooting Connection Issues

If you encounter the "A window handle must be configured" error, this is a known compatibility issue with PowerShell 5.1. To resolve this:

### Recommended Solution (Two-Step Process):
1. Run the `PreAuth-ExchangeOnline.ps1` script first to establish a connection
2. Then run the main script which will reuse the existing connection

### Alternative Solutions:
1. **Manual Connection**: Connect manually using `Connect-ExchangeOnline -ShowBanner:$false` before running the script
2. **Elevated PowerShell**: Try running PowerShell as an administrator
3. **Module Update**: Ensure you have the latest ExchangeOnlineManagement module
4. **Test with Dry Run**: Use the `-DryRun` parameter to test functionality without connecting

## Output

The script generates:
1. Console output showing connection status, summary, and sample data
2. A CSV file in the specified export path with detailed role assignment information

The CSV file includes the following information for each assignment:
- AssignmentId
- AssignmentName
- RoleName
- RoleDescription
- RoleType
- AssigneeId
- AssigneeName
- AssigneeType
- AssigneeEmail
- AssignmentMethod
- RecipientWriteScope
- CustomRecipientWriteScope
- ConfigWriteScope
- CustomConfigWriteScope
- WhenCreated
- WhenChanged

## Dry Run Mode

When using the `-DryRun` switch, the script will:
- Simulate the connection process without actually connecting to Exchange Online
- Return mock data instead of real role assignments
- Show what actions would be performed
- Display where the CSV file would be exported
- Not make any actual changes or connections

This is useful for:
- Testing the script functionality
- Verifying parameters
- Understanding the output format
- Training purposes

## Notes

- The script will automatically disconnect from Exchange Online when finished
- If no TenantId is specified, the script will use the default tenant associated with your account
- The script requires appropriate permissions to read role assignments in Exchange Online
- For PowerShell 5.1 compatibility, the script uses non-interactive connection methods
- The two-step process (pre-authentication + main script) is the most reliable approach for PowerShell 5.1