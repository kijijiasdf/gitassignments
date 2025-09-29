# Quick Reference: Minimum Permissions for Azure Role Assignment Audit Scripts

## 📋 Permission Summary Table

| **Script** | **API Permissions** | **Azure Roles** | **User Roles** |
|------------|--------------------|-----------------|-----------------| 
| **Entra ID Role Assignments** | Directory.Read.All<br/>RoleManagement.Read.All<br/>PrivilegedAccess.Read.AzureAD | N/A | Global Reader (recommended)<br/>Security Reader (minimum)<br/>Privileged Role Administrator (for PIM) |
| **Azure Resource RBAC** | Directory.Read.All<br/>RoleManagement.Read.All<br/>PrivilegedAccess.Read.AzureResources | Reader (at Root MG)<br/>OR Reader (per Subscription)<br/>Security Reader (optional) | Global Reader + Azure Reader<br/>Security Reader (minimum)<br/>Privileged Role Administrator (for PIM) |

## 🔧 Quick Setup Commands

### Grant API Permissions (Admin Required)
```powershell
# For Entra ID script
$appId = "your-app-id"
$permissions = @("Directory.Read.All", "RoleManagement.Read.All", "PrivilegedAccess.Read.AzureAD")

# For Azure Resource script (additional)
$azurePermissions = @("PrivilegedAccess.Read.AzureResources")
```

### Assign Azure Roles (Admin Required)
```powershell
# Grant Reader at root for comprehensive access
New-AzRoleAssignment -SignInName "user@domain.com" -RoleDefinitionName "Reader" -Scope "/"

# Or grant per subscription
New-AzRoleAssignment -SignInName "user@domain.com" -RoleDefinitionName "Reader" -Scope "/subscriptions/your-sub-id"
```

### Test Permissions
```powershell
# Test all permissions
.\Test-AuditPermissions.ps1 -TestAll

# Test specific script permissions
.\Test-AuditPermissions.ps1 -TestEntraIDPermissions
.\Test-AuditPermissions.ps1 -TestAzureResourcePermissions
```

## ⚠️ Common Issues & Quick Fixes

| **Error** | **Cause** | **Quick Fix** |
|-----------|-----------|---------------|
| "Insufficient privileges" | Missing Graph permissions | Request admin consent for required scopes |
| "Cannot access subscription" | Missing Azure Reader role | Request Reader role assignment |
| "PIM access denied" | Missing PIM permissions | Request Privileged Role Administrator role |
| "Empty results" | Insufficient scope | Verify permissions are granted at correct scope level |

## 🌐 Multi-Tenant Checklist

- [ ] App registered as multi-tenant
- [ ] Admin consent granted in each target tenant  
- [ ] User has appropriate roles in each tenant
- [ ] Test permissions with dry-run mode first
- [ ] Verify cross-tenant guest access policies

For complete details, see: [PERMISSIONS_GUIDE.md](PERMISSIONS_GUIDE.md)