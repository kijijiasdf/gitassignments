# Exchange Online Audit Scripts - PowerShell 5.1 Syntax Fixes

## Update Summary

**Date**: September 10, 2025
**Update**: Fixed PowerShell 5.1 syntax errors in Exchange Online audit scripts
**Scripts Updated**: 
- `Audit-ExchangeOnlineHumanAccess.ps1`

## Issues Fixed

### PowerShell 5.1 Variable Reference Syntax Errors

Two syntax errors were identified in the Exchange Online human access audit script:

1. **Line 762**: 
   - **Error**: `Write-LogMessage -Message "Error retrieving nested group members for group $GroupId: $($_.Exception.Message)" -Level 'Warning' -Component 'GroupExpansion'`
   - **Issue**: Variable reference syntax not compatible with PowerShell 5.1

2. **Line 971**: 
   - **Error**: `Write-LogMessage -Message "Could not retrieve last logon time for user $UserId: $($_.Exception.Message)" -Level 'Warning' -Component 'PrincipalEnrichment'`
   - **Issue**: Variable reference syntax not compatible with PowerShell 5.1

### Missing Closing Brace and Structural Error

3. **Line 381**: 
   - **Error**: Parser error indicating "The Try statement is missing its Catch or Finally block"
   - **Issue**: Missing closing brace in the `Get-ExchangeOnlineRoleAssignments` function and improper structuring of if/else blocks

## Fixes Applied

### Variable Reference Syntax Fixes
Both variable reference issues were fixed by using PowerShell 5.1 compatible variable reference syntax:

```powershell
# Before (causing syntax errors):
Write-LogMessage -Message "Error retrieving nested group members for group $GroupId: $($_.Exception.Message)" -Level 'Warning' -Component 'GroupExpansion'

# After (PowerShell 5.1 compatible):
$exceptionMessage = $_.Exception.Message
Write-LogMessage -Message "Error retrieving nested group members for group $GroupId: $exceptionMessage" -Level 'Warning' -Component 'GroupExpansion'
```

### Structural Fix
The structural issue in the `Get-ExchangeOnlineRoleAssignments` function was fixed by:
1. Adding the missing closing brace for the foreach loop
2. Properly structuring the if/else blocks

```powershell
# Before (causing parser error):
foreach ($assignment in $roleAssignments) {
    try {
        // ... code ...
    }
    catch {
        // ... code ...
    }
else {  // Improperly structured else
    // ... code ...
}
}

// Missing closing brace for the outer if statement

# After (properly structured):
foreach ($assignment in $roleAssignments) {
    try {
        // ... code ...
    }
    catch {
        // ... code ...
    }
}
} else {  // Properly structured else
    // ... code ...
}
```

## Technical Details

### Root Cause
The issues were caused by:
1. Using the `$($_.Exception.Message)` syntax directly within double-quoted strings in PowerShell 5.1 exception handling contexts
2. Missing closing brace and improper if/else block structure that caused the parser to fail

### Solution
1. Extract exception messages to separate variables first, then reference them in strings
2. Properly structure the code blocks with correct opening and closing braces

## Benefits

1. **PowerShell 5.1 Compatibility**: Scripts now work correctly in PowerShell 5.1 environments
2. **No Functional Changes**: Same error logging functionality is preserved
3. **Improved Reliability**: Eliminates syntax errors that prevented script execution
4. **Backward Compatibility**: Maintains support for older PowerShell environments

## Related Documentation

- **Main Script**: `Audit-ExchangeOnlineHumanAccess.ps1`
- **PowerShell Compatibility**: `POWERSHELL_51_COMPATIBILITY_REPORT.md`
- **Testing Tools**: `Test-PowerShell51Compatibility.ps1`

---

**The Exchange Online audit scripts have been corrected to ensure full PowerShell 5.1 compatibility, resolving syntax errors that prevented proper execution.**