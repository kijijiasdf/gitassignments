# Enhanced Exchange Online Role Assignments Script

## Overview

This enhanced script provides more detailed and accurate information about Exchange Online role assignments compared to the standard version. It addresses issues with missing data and provides additional details about role group members.

## Improvements Over Standard Version

### 1. Better Data Retrieval
- Enhanced error handling for user, group, and role group lookups
- More robust data extraction for assignee information
- Improved handling of special assignee types (PartnerLinkedRoleGroup)

### 2. Enhanced Data Formatting
- Consistent date formatting (yyyy-MM-dd HH:mm:ss)
- Better description cleanup (removes extra whitespace and newlines)
- Improved handling of missing data with consistent "N/A" values

### 3. Member Details Option
- Optional inclusion of role group members (`-IncludeMemberDetails`)
- Lists all members of role groups for better visibility into access

### 4. Better Progress Reporting
- Progress bar showing completion percentage
- Clear status messages during processing

## Usage

### Standard Usage
```powershell
.\ExchangeOnline-RoleAssignments-Enhanced.ps1
```

### With Member Details (slower but more comprehensive)
```powershell
.\ExchangeOnline-RoleAssignments-Enhanced.ps1 -IncludeMemberDetails
```

### With Custom Export Path
```powershell
.\ExchangeOnline-RoleAssignments-Enhanced.ps1 -ExportPath "C:\Reports"
```

### Dry Run (for testing)
```powershell
.\ExchangeOnline-RoleAssignments-Enhanced.ps1 -DryRun
```

## Output Fields

The enhanced script provides all the fields from the standard version plus:

- **MemberDetails**: Lists members of role groups when `-IncludeMemberDetails` is used

## Troubleshooting

### Missing Assignee Email Addresses
Some assignee types (particularly PartnerLinkedRoleGroup) do not have email addresses by design.

### Long Execution Time with Member Details
Including member details requires additional API calls for each role group, which can significantly increase execution time in large environments.

### Truncated Field Values
Some fields in the CSV output may appear truncated when viewed in Excel. Open the CSV in a text editor or import into Excel properly to see full values.

## Best Practices

1. **Use Standard Version for Quick Audits**: The standard version is faster and sufficient for most auditing needs.

2. **Use Enhanced Version for Detailed Analysis**: When you need member details or more robust data handling.

3. **Schedule Regular Runs**: Run the script regularly to maintain an audit trail of role assignments.

4. **Review Output Carefully**: Pay attention to "N/A" values which may indicate data that couldn't be retrieved.

## Common Issues and Solutions

### Issue: "N/A" in AssigneeEmail Column
**Cause**: Some assignee types don't have email addresses, or there was an error retrieving user details.
**Solution**: Check the AssigneeType column to understand the assignee type.

### Issue: Long Execution Time
**Cause**: Processing many role assignments or using the `-IncludeMemberDetails` parameter.
**Solution**: Run during off-peak hours or without member details for faster execution.

### Issue: Truncated Values in Excel
**Cause**: Excel has a character limit for cell display.
**Solution**: Double-click the cell to see the full value, or use a text editor to view the raw CSV.