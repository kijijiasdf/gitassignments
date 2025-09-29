#Requires -Version 5.1

# Check specific sections for the Error variable issue
$scriptContent = Get-Content "d:\Scripts\Qoder\gitassignments\Audit-AzureAuthMethods.ps1" -Raw

# Look for patterns that might be causing the issue
if ($scriptContent -match '\$Error\s*=') {
    Write-Host "Found explicit Error variable assignment" -ForegroundColor Red
}

if ($scriptContent -match 'param\s*\([^)]*Error[^)]*\)') {
    Write-Host "Found Error in parameter block" -ForegroundColor Red
}

# Check for any hashtable or array definitions with Error
if ($scriptContent -match '@\{[^}]*Error[^}]*\}') {
    Write-Host "Found Error in hashtable definition" -ForegroundColor Yellow
}

if ($scriptContent -match '@\([^)]*Error[^)]*\)') {
    Write-Host "Found Error in array definition" -ForegroundColor Yellow
}

Write-Host "Searching for remaining 'Error' references..." -ForegroundColor Cyan
$lines = Get-Content "d:\Scripts\Qoder\gitassignments\Audit-AzureAuthMethods.ps1"
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '\bError\b' -and $lines[$i] -notmatch '#.*Error' -and $lines[$i] -notmatch 'ErrorAction|ErrorLevel|Error retrieving|Error checking|Error processing') {
        Write-Host "Line $($i+1): $($lines[$i])" -ForegroundColor Red
    }
}