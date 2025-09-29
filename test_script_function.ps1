# Test the updated script function approach
Write-Host "Testing updated script function approach..." -ForegroundColor Yellow

# Define the function as it appears in the updated script
function Connect-ToMicrosoftGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredScopes,
        
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    if ($DryRun) {
        Write-Host "DRY RUN: Would connect to Microsoft Graph for tenant $TenantId" -ForegroundColor Gray
        return $TenantId
    }
    
    try {
        Write-Host "Connecting to Microsoft Graph for tenant: $TenantId" -ForegroundColor Cyan
        
        # Disconnect any existing session
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore disconnect errors
        }
        
        # Connect with required scopes using device code flow
        # Using explicit parameters instead of splatting to ensure device code prompt appears
        Write-Host "Please use the device code displayed in the console to authenticate." -ForegroundColor Yellow
        Write-Host "If you don't see the device code prompt, please check the console window for authentication instructions." -ForegroundColor Yellow
        
        $connection = Connect-MgGraph -TenantId $TenantId -Scopes $RequiredScopes -UseDeviceCode
        
        $newContext = Get-MgContext
        
        Write-Host "Successfully connected to tenant: $($newContext.TenantId)" -ForegroundColor Green
        Write-Host "Available scopes: $($newContext.Scopes -join ', ')" -ForegroundColor Gray
        
        return $newContext.TenantId
    }
    catch {
        Write-Host "Failed to connect to Microsoft Graph for tenant $($TenantId): $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

# Test the function
try {
    Write-Host "`nCalling Connect-ToMicrosoftGraph function..." -ForegroundColor Cyan
    $result = Connect-ToMicrosoftGraph -TenantId "75bf4402-ab2f-47d4-82cf-c9c3cf971dcc" -RequiredScopes @("Directory.Read.All", "RoleManagement.Read.All")
    Write-Host "Function completed successfully with result: $result" -ForegroundColor Green
    Disconnect-MgGraph -ErrorAction SilentlyContinue
} catch {
    Write-Host "Function failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nTest complete." -ForegroundColor Yellow