# Quick Reference: Exchange Online Audit Scripts Permissions

## 📋 Permission Summary Table

| **Script** | **Microsoft Graph Permissions** | **Exchange Online Roles** | **Azure AD Roles** |
|------------|--------------------------------|---------------------------|-------------------|
| **Human Access Audit** | Directory.Read.All<br/>RoleManagement.Read.All<br/>PrivilegedAccess.Read.AzureAD | View-Only Organization Management<br/>(or Exchange Administrator) | Global Reader (recommended)<br/>Security Reader (minimum)<br/>Privileged Role Administrator (for PIM) |
| **Non-Human Access Audit** | Directory.Read.All<br/>Application.Read.All<br/>AppRoleAssignment.Read.All | View-Only Organization Management<br/>(or Exchange Administrator) | Global Reader (recommended)<br/>Security Reader (minimum)<br/>Application Administrator |

## 🔧 Quick Setup Commands

### Grant Microsoft Graph Permissions (Admin Required)
```powershell
# Connect to Microsoft Graph with admin account
Connect-MgGraph -Scopes "Application.ReadWrite.All"

# For Human Access script permissions
$appId = "your-app-id"
$requiredPermissions = @("Directory.Read.All", "RoleManagement.Read.All", "PrivilegedAccess.Read.AzureAD")

# For Non-Human Access script permissions  
$appId = "your-app-id"
$requiredPermissions = @("Directory.Read.All", "Application.Read.All", "AppRoleAssignment.Read.All")

# Grant admin consent (requires Global Administrator)
foreach ($permission in $requiredPermissions) {
    # Use Azure portal or PowerShell to grant admin consent
}
```

### Assign Exchange Online Roles (Exchange Admin Required)
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Grant View-Only Organization Management (minimum required)
Add-RoleGroupMember -Identity "View-Only Organization Management" -Member "user@domain.com"

# OR grant Exchange Administrator (for full access)
Add-RoleGroupMember -Identity "Organization Management" -Member "user@domain.com"
```

### Assign Azure AD Roles (Global Admin Required)
```powershell
# Connect to Azure AD
Connect-AzureAD

# Grant Global Reader (recommended)
$userId = (Get-AzureADUser -ObjectId "user@domain.com").ObjectId
$roleId = (Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Reader"}).ObjectId
Add-AzureADDirectoryRoleMember -ObjectId $roleId -RefObjectId $userId

# OR grant Security Reader (minimum)
$roleId = (Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Security Reader"}).ObjectId
Add-AzureADDirectoryRoleMember -ObjectId $roleId -RefObjectId $userId
```

## 🧪 Test Permissions

### Quick Permission Test
```powershell
# Test all permissions for both scripts
.\Test-ExchangeOnlinePermissions.ps1 -TestAll

# Test specific script permissions
.\Test-ExchangeOnlinePermissions.ps1 -TestHumanAccess
.\Test-ExchangeOnlinePermissions.ps1 -TestNonHumanAccess

# Test with specific tenant
.\Test-ExchangeOnlinePermissions.ps1 -TestAll -TenantId "your-tenant-id"
```

### Manual Permission Verification
```powershell
# Test Microsoft Graph connectivity
Connect-MgGraph -Scopes "Directory.Read.All"
Get-MgUser -Top 1

# Test Exchange Online connectivity  
Connect-ExchangeOnline
Get-ManagementRoleAssignment -ResultSize 1

# Test PIM permissions (for Human Access script)
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Top 1

# Test Application permissions (for Non-Human Access script)
Get-MgApplication -Top 1
Get-MgServicePrincipal -Top 1
```

## ⚠️ Troubleshooting Common Issues

### "Insufficient privileges" Error
**Solution**: Grant the required API permissions and ensure admin consent

### "Access denied" in Multi-Tenant
**Solution**: Ensure admin consent in target tenant and verify user roles

### Exchange Online Connection Fails  
**Solution**: Verify Exchange Online licensing and role assignments

### PIM Data Not Available
**Solution**: Ensure PIM is enabled and PrivilegedAccess.Read.AzureAD permission is granted

## 📚 Additional Resources

- **Detailed Guide**: `EXCHANGE_ONLINE_PERMISSIONS_GUIDE.md`
- **Permission Test Script**: `Test-ExchangeOnlinePermissions.ps1`
- **Human Access Audit**: `Audit-ExchangeOnlineHumanAccess.ps1`
- **Non-Human Access Audit**: `Audit-ExchangeOnlineNonHumanAccess.ps1`

## 🔗 Related Links

- [Microsoft Graph Permissions Reference](https://docs.microsoft.com/en-us/graph/permissions-reference)
- [Exchange Online PowerShell](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)
- [Azure AD Roles Documentation](https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)