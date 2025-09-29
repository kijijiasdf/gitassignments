# Azure Authentication Methods Audit Script - Permissions Guide

## Overview
This document outlines the minimum required permissions and access requirements for the `Audit-AzureAuthMethods.ps1` script, which audits Azure Entra ID authentication methods for all member users with NIST AAL compliance analysis.

## Script Purpose
The script inventories authentication methods across member users to support phishing-resistant passwordless MFA implementation planning. It provides:
- Comprehensive authentication method inventory (Authenticator, FIDO2, SMS, Voice, Email, WHFB, CBA, TAP, OATH)
- NIST AAL (Authenticator Assurance Level) compliance classification
- Phishing-resistant method identification
- Gap analysis for passwordless transition
- Multi-tenant support with consolidated reporting

## Required Microsoft Graph API Permissions

### Minimum Application Permissions
When running as an application (service principal):

| Permission | Type | Purpose | Scope |
|------------|------|---------|-------|
| `User.Read.All` | Application | Read all user profiles and basic information | Required |
| `UserAuthenticationMethod.Read.All` | Application | Read all users' authentication methods | Required |
| `Policy.Read.All` | Application | Read authentication method policies | Required |

### Minimum Delegated Permissions
When running with user authentication:

| Permission | Type | Purpose | Scope |
|------------|------|---------|-------|
| `User.Read.All` | Delegated | Read all user profiles and basic information | Required |
| `UserAuthenticationMethod.Read.All` | Delegated | Read all users' authentication methods | Required |
| `Policy.Read.All` | Delegated | Read authentication method policies | Required |

## Required Azure AD User Roles

### Recommended Role
- **Global Reader**: Provides comprehensive read access to all Azure AD objects including authentication methods, users, and policies

### Minimum Role Options
- **Security Reader**: Basic security-related read access with authentication method visibility
- **Authentication Administrator**: Enhanced authentication method insights and configuration visibility

### Multi-Tenant Considerations
- User must have appropriate roles in **each target tenant**
- Cross-tenant guest users may have limited visibility depending on external collaboration settings
- Admin consent required for the application in each tenant

## Authentication Method Coverage

The script audits the following authentication methods with their NIST AAL classification:

### AAL1 (Single-factor)
- Password authentication
- Email verification

### AAL2 (Multi-factor)
- Microsoft Authenticator app
- SMS verification
- Voice/Phone call verification
- Software OATH tokens
- Hardware OATH tokens

### AAL3 (Phishing-resistant)
- FIDO2 security keys
- Certificate-based authentication (CBA)
- Windows Hello for Business (WHFB)

## Specific Graph API Endpoints

The script accesses these Microsoft Graph endpoints:

### User Information
- `GET /users` - Retrieve member users (filtered by userType eq 'Member')
- `GET /users/{id}` - Individual user details

### Authentication Methods
- `GET /users/{id}/authentication/microsoftAuthenticatorMethods`
- `GET /users/{id}/authentication/fido2Methods`
- `GET /users/{id}/authentication/phoneMethods`
- `GET /users/{id}/authentication/emailMethods`
- `GET /users/{id}/authentication/softwareOathMethods`
- `GET /users/{id}/authentication/windowsHelloForBusinessMethods`
- `GET /users/{id}/authentication/temporaryAccessPassMethods`

### User Preferences
- `GET /users/{id}/authentication/signInPreferences`

## Application Registration Requirements

### Single Tenant Application
```json
{
  "requiredResourceAccess": [
    {
      "resourceAppId": "00000003-0000-0000-c000-000000000000",
      "resourceAccess": [
        {
          "id": "df021288-bdef-4463-88db-98f22de89214",
          "type": "Role"
        },
        {
          "id": "38d9df27-64da-44fd-b7c5-a6fbac20248f",
          "type": "Role"
        },
        {
          "id": "246dd0d5-5bd0-4def-940b-0421030a5b68",
          "type": "Role"
        }
      ]
    }
  ]
}
```

### Multi-Tenant Application
- Set `signInAudience` to `AzureADMultipleOrgs`
- Obtain admin consent in each target tenant
- Ensure proper role assignments in each tenant

## Permission Validation

Use the companion `Test-AuditPermissions.ps1` script to validate permissions:

```powershell
# Test authentication methods permissions
.\Test-AuditPermissions.ps1 -TestAuthMethods

# Test all components
.\Test-AuditPermissions.ps1 -TestAll
```

## Troubleshooting

### Common Permission Issues

#### "Insufficient privileges" Error
- **Cause**: Missing UserAuthenticationMethod.Read.All permission
- **Solution**: Grant the required permission and obtain admin consent

#### "Access denied" for specific users
- **Cause**: User may be in external tenant or have restricted access
- **Solution**: Verify user type and cross-tenant access policies

#### Empty authentication methods returned
- **Cause**: Missing Policy.Read.All permission or authentication method policies
- **Solution**: Grant Policy.Read.All permission and verify authentication method configuration

### Permission Verification Commands

```powershell
# Check current Graph context and permissions
Get-MgContext | Select-Object -Property TenantId, Scopes, Account

# Test user read access
Get-MgUser -Filter "userType eq 'Member'" -Top 1

# Test authentication method access
$user = Get-MgUser -Top 1
Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user.Id
```

## Compliance and Security

### Data Access
- Script operates in read-only mode
- No authentication methods are modified
- User privacy maintained through aggregated reporting

### Audit Trail
- All operations logged with timestamps
- Failed operations recorded with error details
- Complete audit trail available in CSV log files

### Data Retention
- Generated reports contain sensitive authentication method data
- Follow organizational data retention policies
- Secure storage and transmission of reports recommended

## Multi-Tenant Deployment

### Prerequisites
1. Multi-tenant app registration
2. Admin consent in each target tenant
3. Appropriate role assignments for executing user
4. Network connectivity to all target tenants

### Execution Pattern
```powershell
# Multi-tenant execution
.\Audit-AzureAuthMethods.ps1 -TenantIds @("tenant1", "tenant2") -ExportPath "C:\Reports"

# Single tenant with device details
.\Audit-AzureAuthMethods.ps1 -TenantIds @("tenant1") -IncludeDeviceDetails

# Dry-run testing
.\Audit-AzureAuthMethods.ps1 -TenantIds @("tenant1") -DryRun
```

## Additional Resources

- [Microsoft Graph permissions reference](https://docs.microsoft.com/en-us/graph/permissions-reference)
- [Authentication methods API documentation](https://docs.microsoft.com/en-us/graph/api/resources/authenticationmethods-overview)
- [NIST AAL Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Azure AD authentication methods documentation](https://docs.microsoft.com/en-us/azure/active-directory/authentication/)

---
*Generated for Audit-AzureAuthMethods.ps1 v1.0*  
*Last Updated: 2025-09-03*