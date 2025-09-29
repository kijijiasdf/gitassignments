# Testing Device Code Authentication

## Overview
This document explains how to test and verify that device code authentication is working correctly with the Exchange Online audit scripts.

## What to Expect

When you run either of the Exchange Online audit scripts, you should see the following sequence:

1. **Log Messages**: The script will log messages indicating that device code authentication is being used:
   ```
   [2025-09-25 23:59:32] [GraphConnection] [Information] Connecting to Microsoft Graph for tenant: 75bf4402-ab2f-47d4-82cf-c9c3cf971dcc
   [2025-09-25 23:59:32] [GraphConnection] [Information] Please use the device code displayed in the console to authenticate.
   [2025-09-25 23:59:32] [GraphConnection] [Information] If you don't see the device code prompt, please check the console window for authentication instructions.
   ```

2. **Device Code Prompt**: Immediately after the log messages, you should see the device code authentication prompt directly in the console window (not in the log):
   ```
   To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXX to authenticate.
   ```

3. **Authentication Process**: 
   - Open a web browser and navigate to https://microsoft.com/devicelogin
   - Enter the code provided in the console
   - Sign in with your Azure AD credentials
   - Grant the necessary permissions to the application

4. **Successful Connection**: After successful authentication, the script will continue with log messages:
   ```
   [2025-09-25 23:59:45] [GraphConnection] [Information] Successfully connected to tenant: 75bf4402-ab2f-47d4-82cf-c9c3cf971dcc
   [2025-09-25 23:59:45] [GraphConnection] [Verbose] Available scopes: Directory.Read.All, RoleManagement.Read.All
   ```

## Troubleshooting

### If You Don't See the Device Code Prompt

1. **Check the Console Window**: The device code prompt appears directly in the console window, not in the logged output. Look at your PowerShell console window for the prompt.

2. **Run in Foreground**: Ensure you're running the script in a foreground PowerShell session, not as a background job.

3. **Check for Errors**: Look for any error messages in the log that might indicate authentication issues.

### Common Authentication Issues

1. **Insufficient Permissions**: Ensure your account has the necessary permissions to access the Exchange Online and Microsoft Graph APIs.

2. **App Registration Issues**: Verify that the app registration used by the Microsoft Graph PowerShell module has the required API permissions.

3. **Network Issues**: Ensure you have internet connectivity and can access https://microsoft.com/devicelogin.

## Testing with Dry Run

You can test the authentication flow without actually connecting to Exchange Online by using the `-DryRun` parameter:

```powershell
.\Audit-ExchangeOnlineHumanAccess.ps1 -TenantIds @("your-tenant-id") -DryRun
```

This will simulate the authentication process and show you what would happen without actually connecting to the services.

## Benefits of Device Code Authentication

1. **No Browser Required on the Same Machine**: You can authenticate using any device with a web browser.
2. **Enhanced Security**: Reduces the risk of credential interception.
3. **Better for Automation**: More reliable in automated environments.
4. **Cross-Platform Compatibility**: Works consistently across different operating systems.