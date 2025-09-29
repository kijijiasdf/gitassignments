# Exchange Online PowerShell Permissions and Connection Guide

## Table of Contents
1. [Required Permissions](#required-permissions)
2. [Module Installation](#module-installation)
3. [Connection Methods](#connection-methods)
4. [PowerShell 5.1 Compatibility](#powershell-51-compatibility)
5. [Troubleshooting](#troubleshooting)

## Required Permissions

To run Exchange Online audit scripts, you need one of the following roles:

- **Global Administrator**
- **Exchange Administrator** 
- **Exchange Recipient Administrator**
- **Help Desk Administrator** (limited functionality)
- **Security Administrator** (read-only access to most cmdlets)

For role assignment auditing specifically, you need:
- **View-Only Organization Management** role or higher
- **Security Administrator** role (can view but not modify role assignments)
- **Organization Management** role (full access)

## Module Installation

### Installing Exchange Online PowerShell Module

```powershell
# Install the module
Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser

# Import the module
Import-Module ExchangeOnlineManagement
```

### Verifying Installation

```powershell
# Check if module is installed
Get-Module -ListAvailable -Name ExchangeOnlineManagement

# Check module version
Get-Module ExchangeOnlineManagement | Select-Object Name, Version
```

## Connection Methods

### Standard Connection

```powershell
# Connect with minimal parameters
Connect-ExchangeOnline -ShowBanner:$false

# Connect to a specific organization
Connect-ExchangeOnline -Organization "yourdomain.onmicrosoft.com" -ShowBanner:$false
```

### Connection with Existing Session Management

```powershell
# Check for existing connection
$existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
if ($existingConnection) {
    Write-Host "Using existing connection" -ForegroundColor Green
} else {
    # Connect with proper error handling
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
}
```

## PowerShell 5.1 Compatibility

### Window Handle Issue

PowerShell 5.1 has known compatibility issues with Exchange Online authentication that can cause the following error:

```
Error Acquiring Token:
A window handle must be configured. See https://aka.ms/msal-net-wam#parent-window-handles
```

### Solutions for PowerShell 5.1

1. **Use explicit connection parameters:**
   ```powershell
   Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
   ```

2. **Implement proper connection management:**
   ```powershell
   # Check for existing connection
   $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
   if (-not $existingConnection) {
       # Disconnect any stale sessions
       Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
       
       # Connect with compatible parameters
       Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
   }
   ```

3. **Use device code authentication as a fallback:**
   ```powershell
   Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop
   ```

## Troubleshooting

### Common Connection Issues

1. **"A window handle must be configured" Error**
   - **Cause:** PowerShell 5.1 compatibility issue with interactive authentication
   - **Solution:** Use the connection methods described in the PowerShell 5.1 Compatibility section above

2. **"The term 'Connect-ExchangeOnline' is not recognized"**
   - **Cause:** Module not installed or imported
   - **Solution:** Install and import the ExchangeOnlineManagement module

3. **"Access Denied" or "Insufficient Permissions"**
   - **Cause:** User account lacks required permissions
   - **Solution:** Ensure your account has the appropriate Exchange Online administrative role

4. **"The module 'ExchangeOnlineManagement' could not be installed"**
   - **Cause:** Execution policy restrictions
   - **Solution:** Set execution policy with `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

5. **"The underlying connection was closed"**
   - **Cause:** Network connectivity issues or TLS configuration
   - **Solution:** Check internet connectivity and ensure TLS 1.2 is enabled

### Testing Connection

```powershell
# Test basic connectivity
Get-OrganizationConfig

# Test role assignment access
Get-ManagementRoleAssignment -ResultSize 1

# Check connection information
Get-ConnectionInformation
```

### Connection Cleanup

```powershell
# Disconnect properly when finished
Disconnect-ExchangeOnline -Confirm:$false
```

## Additional Resources

- [Exchange Online PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)
- [Exchange Online Protection (EOP) PowerShell](https://docs.microsoft.com/en-us/powershell/exchange/exchange-eop/exchange-eop-powershell)
- [Security & Compliance Center PowerShell](https://docs.microsoft.com/en-us/powershell/exchange/scc-powershell)