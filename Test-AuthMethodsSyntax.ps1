#Requires -Version 5.1

# Test syntax validation for the auth methods script
$scriptPath = "d:\Scripts\Qoder\gitassignments\Audit-AzureAuthMethods.ps1"

try {
    $syntaxErrors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$syntaxErrors)
    
    if ($syntaxErrors.Count -gt 0) {
        Write-Host "Syntax errors found:" -ForegroundColor Red
        foreach ($error in $syntaxErrors) {
            Write-Host "Line $($error.Extent.StartLineNumber): $($error.Message)" -ForegroundColor Red
            Write-Host "Text: $($error.Extent.Text)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "No syntax errors found!" -ForegroundColor Green
    }
}
catch {
    Write-Host "Error during parsing: $($_.Exception.Message)" -ForegroundColor Red
}