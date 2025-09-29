# Test script for Exchange Online connection - Fixed Version
Write-Host "Testing Exchange Online connection (Fixed Version)..." -ForegroundColor Yellow

try {
    # Import Exchange Online module
    Write-Host "Importing Exchange Online module..." -ForegroundColor Yellow
    Import-Module ExchangeOnlineManagement -Force -ErrorAction Stop
    Write-Host "Exchange Online module imported successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Exchange Online module: $($_.Exception.Message)"
    exit 1
}

try {
    Write-Host "Checking for existing connection..." -ForegroundColor Cyan
    
    # Check if already connected
    $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($existingConnection) {
        Write-Host "Using existing Exchange Online connection" -ForegroundColor Green
        Write-Host "Connection state: $($existingConnection.State)" -ForegroundColor Gray
    } else {
        Write-Host "No existing connection found. Attempting to connect..." -ForegroundColor Cyan
        
        # Disconnect any existing session first
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        
        # Use the most compatible connection approach for PowerShell 5.1
        Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        
        Write-Host "Successfully connected to Exchange Online!" -ForegroundColor Green
    }
    
    # Test a simple command
    Write-Host "Testing connection with Get-OrganizationConfig..." -ForegroundColor Yellow
    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
    Write-Host "Organization Name: $($orgConfig.Name)" -ForegroundColor Green
    Write-Host "Primary Domain: $($orgConfig.DefaultDomainName)" -ForegroundColor Green
    
    Write-Host "Connection test completed successfully!" -ForegroundColor Green
    
} catch [System.Management.Automation.CmdletInvocationException] {
    if ($_.Exception.Message -like "*window handle*" -or $_.Exception.Message -like "*WAM*") {
        Write-Warning "Encountered PowerShell 5.1 window handle issue. Trying alternative approach..."
        
        try {
            # Alternative connection method
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
            $orgConfig = Get-OrganizationConfig -ErrorAction Stop
            Write-Host "Organization Name: $($orgConfig.Name)" -ForegroundColor Green
            Write-Host "Alternative connection method successful!" -ForegroundColor Green
        } catch {
            Write-Error "Alternative connection method also failed: $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
        exit 1
    }
} catch {
    Write-Error "Failed to connect to Exchange Online: $($_.Exception.Message)"
    exit 1
}

Write-Host "Test completed successfully!" -ForegroundColor Green