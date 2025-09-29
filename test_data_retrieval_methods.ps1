# Test different data retrieval methods for Exchange Online objects
# This script demonstrates the various methods we can use to retrieve user/group details

Write-Host "Testing different data retrieval methods for Exchange Online objects" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan

# Function to test a method
function Test-Method {
    param(
        [string]$MethodName,
        [scriptblock]$ScriptBlock
    )
    
    Write-Host "`nTesting $MethodName..." -ForegroundColor Yellow
    try {
        $result = & $ScriptBlock
        if ($result) {
            Write-Host "  SUCCESS: Data retrieved" -ForegroundColor Green
            # Show first result as example
            $firstItem = $result | Select-Object -First 1
            Write-Host "  Sample: $($firstItem | Out-String)" -ForegroundColor Gray
        } else {
            Write-Host "  NO DATA: Method worked but returned no results" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "This script shows the different methods available for retrieving user and group information." -ForegroundColor Gray
Write-Host "In the improved role assignments script, we use these methods in fallback chains:" -ForegroundColor Gray
Write-Host "1. Try the most specific cmdlet first (Get-User, Get-Group, Get-RoleGroup)" -ForegroundColor Gray
Write-Host "2. Fall back to Get-Recipient for generic recipient information" -ForegroundColor Gray
Write-Host "3. Handle errors gracefully and provide meaningful N/A values" -ForegroundColor Gray

Write-Host "`nExample method chain for Users:" -ForegroundColor Cyan
Write-Host "1. Get-User -Identity <user>" -ForegroundColor Gray
Write-Host "2. If that fails, try Get-Recipient -Identity <user>" -ForegroundColor Gray

Write-Host "`nExample method chain for Groups:" -ForegroundColor Cyan
Write-Host "1. Get-Group -Identity <group>" -ForegroundColor Gray
Write-Host "2. If that fails, try Get-Recipient -Identity <group>" -ForegroundColor Gray

Write-Host "`nExample method chain for RoleGroups:" -ForegroundColor Cyan
Write-Host "1. Get-RoleGroup -Identity <rolegroup>" -ForegroundColor Gray

Write-Host "`nKey Properties to Retrieve:" -ForegroundColor Cyan
Write-Host "- PrimarySmtpAddress (email address)" -ForegroundColor Gray
Write-Host "- DisplayName (friendly name)" -ForegroundColor Gray
Write-Host "- UserPrincipalName (for users)" -ForegroundColor Gray
Write-Host "- WindowsEmailAddress (for role groups)" -ForegroundColor Gray

Write-Host "`nData Quality Improvements in Improved Script:" -ForegroundColor Cyan
Write-Host "- String conversion to prevent null values" -ForegroundColor Gray
Write-Host "- Trimming whitespace" -ForegroundColor Gray
Write-Host "- Consistent 'N/A' values for missing data" -ForegroundColor Gray
Write-Host "- Better error handling and logging" -ForegroundColor Gray

Write-Host "`nScript completed." -ForegroundColor Green