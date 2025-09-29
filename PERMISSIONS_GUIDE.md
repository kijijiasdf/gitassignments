# Azure Role Assignment Audit Scripts - Permissions & Prerequisites

## Overview
This document outlines the minimum API permissions and user roles required to successfully execute the Azure role assignment audit scripts across single and multi-tenant environments.

## 📋 Script 1: Audit-EntraIDRoleAssignments.ps1

### Microsoft Graph API Permissions

#### Required Application Permissions
```
Directory.Read.All
- Purpose: Read user, group, and service principal information
- Scope: Tenant-wide directory reading capabilities
- Required for: Principal enrichment and group member expansion

RoleManagement.Read.All  
- Purpose: Read role definitions and direct role assignments
- Scope: All Azure AD roles and assignments
- Required for: Core role assignment auditing

PrivilegedAccess.Read.AzureAD
- Purpose: Read PIM (Privileged Identity Management) data
- Scope: Azure AD PIM eligible and active assignments
- Required for: PIM detection and PIM assignment auditing
```

#### Required Delegated Permissions (Interactive Sign-in)
```
Directory.Read.All
RoleManagement.Read.All
PrivilegedAccess.Read.AzureAD
```

### Minimum User Roles

#### Recommended Roles
- **Global Reader**: Provides comprehensive read access to Azure AD
- **Privileged Role Administrator**: Required for full PIM data access

#### Minimum Roles  
- **Security Reader**: Basic role visibility (limited PIM access)
- **Directory Readers**: Basic directory information (no role assignments)

### Permission Verification Commands
```powershell
# Check current user's roles
Get-MgUserMemberOf -UserId (Get-MgContext).Account

# Check Graph permissions
Get-MgContext | Select-Object Scopes

# Test PIM access
Get-MgIdentityGovernancePrivilegedAccessResource -PrivilegedAccessId 'aadRoles' -Top 1
```

---

## 📋 Script 2: Audit-AzureResourceRBAC.ps1

### Microsoft Graph API Permissions

#### Required Application Permissions
```
Directory.Read.All
- Purpose: Read user, group, and service principal information  
- Scope: Tenant-wide directory reading for principal enrichment
- Required for: Enriching Azure role assignments with identity details

RoleManagement.Read.All
- Purpose: Read Azure resource role definitions
- Scope: Azure RBAC role definitions and metadata
- Required for: Role definition enrichment

PrivilegedAccess.Read.AzureResources
- Purpose: Read Azure PIM data for resources
- Scope: Azure resource PIM eligible and active assignments
- Required for: Azure PIM detection and assignment auditing
```

### Azure RBAC Permissions

#### Recommended Permissions
```
Reader (at Root Management Group)
- Purpose: Comprehensive access to all subscriptions and resources
- Scope: Entire Azure hierarchy
- Provides: Management groups, subscriptions, resource groups, resources

Security Reader (Azure-wide)
- Purpose: Enhanced security insights across Azure resources
- Scope: All Azure resources
- Provides: Security-related role assignments and policies
```

#### Minimum Permissions
```
Reader (per Subscription)
- Purpose: Access to specific subscriptions only
- Scope: Individual subscription level
- Limitation: No management group visibility

Reader (per Resource Group)
- Purpose: Access to specific resource groups
- Scope: Individual resource group level
- Limitation: No subscription or management group visibility
```

### Azure PowerShell Role Requirements
```
# Minimum Azure PowerShell permissions
Get-AzRoleAssignment -Scope "/" # Requires Reader at root
Get-AzSubscription              # Requires Reader on subscriptions
Get-AzManagementGroup          # Requires Reader on management groups
```

---

## 🌐 Multi-Tenant Considerations

### Cross-Tenant Application Registration
For automated multi-tenant scenarios, register an application with:

```
Application Type: Multi-tenant
Required Permissions: All permissions listed above
Admin Consent: Required in each target tenant
Authentication: Service Principal or Certificate-based
```

### Per-Tenant Requirements
Each target tenant must have:

1. **Application consent granted** for required permissions
2. **User account access** with appropriate roles
3. **Guest user limitations** considered (external users may have restricted visibility)

### Guest User Limitations
```
External Guest Users may experience:
- Limited directory visibility
- Restricted PIM access
- Reduced role assignment visibility
- Dependency on host tenant's guest access policies
```

---

## ⚠️ Common Permission Issues & Solutions

### Issue 1: "Insufficient privileges to complete the operation"
**Cause**: Missing Graph API permissions or insufficient Azure roles
**Solution**: 
```powershell
# Verify Graph permissions
Get-MgContext | Select-Object Scopes

# Check Azure role assignments
Get-AzRoleAssignment -SignInName (Get-AzContext).Account.Id
```

### Issue 2: "Access denied when accessing PIM data"
**Cause**: Missing PrivilegedAccess permissions or insufficient role
**Solution**:
- Ensure `PrivilegedAccess.Read.AzureAD` (for Entra ID PIM)
- Ensure `PrivilegedAccess.Read.AzureResources` (for Azure PIM)
- Verify user has Privileged Role Administrator or Global Reader role

### Issue 3: "Cannot access subscription/management group"
**Cause**: Insufficient Azure RBAC permissions
**Solution**:
```powershell
# Request Reader role at appropriate scope
New-AzRoleAssignment -SignInName user@domain.com -RoleDefinitionName "Reader" -Scope "/"
```

### Issue 4: "Empty results in multi-tenant scenario"
**Cause**: Application not consented in target tenant
**Solution**:
- Verify app registration is multi-tenant
- Ensure admin consent granted in each tenant
- Check tenant-specific permission grants

---

## 🔧 Pre-Execution Checklist

### Before Running Scripts
- [ ] Verify Graph API permissions granted
- [ ] Confirm Azure RBAC permissions assigned
- [ ] Test PIM access (if applicable)
- [ ] Validate multi-tenant app consent (if applicable)
- [ ] Confirm target tenant accessibility
- [ ] Test dry-run mode first

### Permission Testing Commands
```powershell
# Test Entra ID permissions
Get-MgDirectoryRole -Top 1
Get-MgUser -Top 1
Get-MgIdentityGovernancePrivilegedAccessResource -PrivilegedAccessId 'aadRoles' -Top 1

# Test Azure permissions  
Get-AzSubscription
Get-AzManagementGroup
Get-AzRoleAssignment -Scope "/" -Top 1
Get-MgIdentityGovernancePrivilegedAccessResource -PrivilegedAccessId 'azureResources' -Top 1
```

---

## 📞 Support & Troubleshooting

### Microsoft Documentation References
- [Graph API Permissions](https://docs.microsoft.com/en-us/graph/permissions-reference)
- [Azure RBAC Built-in Roles](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
- [PIM API Permissions](https://docs.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagement-resources)

### Permission Escalation Process
1. **Identify specific missing permission** using error messages
2. **Request minimum required role** from tenant administrator
3. **Test permissions** using dry-run mode
4. **Escalate gradually** if broader access needed
5. **Document business justification** for each permission request

---

*Last Updated: $(Get-Date -Format 'yyyy-MM-dd')*
*Version: 1.0*