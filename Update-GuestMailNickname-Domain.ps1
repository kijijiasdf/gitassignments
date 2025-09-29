<#
.SYNOPSIS
    Updates guest user MailNickname attribute in Azure Entra ID to change domain references.
.DESCRIPTION
    Processes a CSV of guest users and updates their MailNickname to replace old domain with new domain.
    Example: lucas.kerjan_pf-gt.com#EXT# -> lucas.kerjan_pf.gt.com#EXT#
.PARAMETER CsvPath
    Path to CSV file containing user information (ObjectId or UserPrincipalName columns required)
.PARAMETER RealMode
    Switch to enable actual changes. Without this, script runs in dry-run mode.
.PARAMETER SearchDomain
    Domain string to replace in MailNickname (e.g., "pf-gt.com")
.PARAMETER NewDomain
    New domain string to use (e.g., "pf.gt.com")
.PARAMETER TenantId
    Azure tenant ID (optional - will prompt if not provided)
.NOTES
    PowerShell 5.1 + Microsoft.Graph module required.
    Requires User.ReadWrite.All permission scope.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [string]$SearchDomain,
    
    [Parameter(Mandatory = $false)]
    [string]$NewDomain,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [switch]$RealMode
)

# Validate required modules
$RequiredModules = @("Microsoft.Graph.Users", "Microsoft.Graph.Authentication")
foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -ListAvailable -Name $Module)) {
        Write-Error "$Module module not found. Install with 'Install-Module Microsoft.Graph' (as Admin)."
        exit 1
    }
}

# Import required modules
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Authentication

# Validate CSV file exists
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: $CsvPath"
    exit 1
}

# Get parameters if not provided
if (-not $TenantId) {
    $TenantId = Read-Host "Enter your Azure Tenant ID"
}
if (-not $SearchDomain) {
    $SearchDomain = Read-Host "Enter the domain string to replace (e.g., pf-gt.com)"
}
if (-not $NewDomain) {
    $NewDomain = Read-Host "Enter the new domain string (e.g., pf.gt.com)"
}

# Validate inputs
if ([string]::IsNullOrWhiteSpace($SearchDomain) -or [string]::IsNullOrWhiteSpace($NewDomain)) {
    Write-Error "SearchDomain and NewDomain cannot be empty"
    exit 1
}

if ($SearchDomain -eq $NewDomain) {
    Write-Error "SearchDomain and NewDomain cannot be identical"
    exit 1
}

Write-Host "=== Azure Guest User MailNickname Update Script ===" -ForegroundColor Magenta
Write-Host "Search Domain: $SearchDomain" -ForegroundColor White
Write-Host "New Domain: $NewDomain" -ForegroundColor White
Write-Host "Mode: $(if($RealMode){'LIVE CHANGES'}else{'DRY RUN'})" -ForegroundColor $(if($RealMode){'Red'}else{'Yellow'})
Write-Host ""

# Connect to Microsoft Graph
try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "User.ReadWrite.All" -TenantId $TenantId -ErrorAction Stop
    $Context = Get-MgContext
    Write-Host "Connected to tenant: $($Context.TenantId)" -ForegroundColor Green
} catch {
    Write-Error "Could not connect to Microsoft Graph: $_"
    exit 1
}

# Import and validate CSV
try {
    $Users = Import-Csv -Path $CsvPath
    Write-Host "Loaded $($Users.Count) users from CSV" -ForegroundColor Cyan
} catch {
    Write-Error "Failed to import CSV: $_"
    exit 1
}

# Validate CSV has required columns
$FirstUser = $Users | Select-Object -First 1
if (-not ($FirstUser.PSObject.Properties.Name -contains "ObjectId" -or $FirstUser.PSObject.Properties.Name -contains "UserPrincipalName")) {
    Write-Error "CSV must contain either 'ObjectId' or 'UserPrincipalName' column"
    exit 1
}

# Initialize counters
$ProcessedCount = 0
$UpdatedCount = 0
$SkippedCount = 0
$ErrorCount = 0
$Results = @()

foreach ($Row in $Users) {
    $ProcessedCount++
    
    # Get user identifier
    $UserId = $Row.ObjectId
    if (-not $UserId) { $UserId = $Row.UserPrincipalName }
    if (-not $UserId) { 
        Write-Warning "Row ${ProcessedCount}: No ObjectId or UPN found - skipping"
        $SkippedCount++
        continue 
    }

    Write-Host "`n[$ProcessedCount/$($Users.Count)] Processing: $UserId" -ForegroundColor White

    try {
        # Get user details
        $User = Get-MgUser -UserId $UserId -Property "Id,UserPrincipalName,Mail,MailNickname,DisplayName,UserType" -ErrorAction Stop
        
        # Verify this is a guest user
        if ($User.UserType -ne "Guest") {
            Write-Host "  SKIP: Not a guest user ($($User.UserType))" -ForegroundColor Yellow
            $SkippedCount++
            continue
        }

        # Check if MailNickname contains the search domain
        $CurrentMailNick = $User.MailNickname
        if ([string]::IsNullOrEmpty($CurrentMailNick) -or $CurrentMailNick -notlike "*$SearchDomain*") {
            Write-Host "  SKIP: MailNickname doesn't contain '$SearchDomain' or is empty" -ForegroundColor Yellow
            $SkippedCount++
            continue
        }

        # Calculate new MailNickname
        $NewMailNick = $CurrentMailNick -replace [regex]::Escape($SearchDomain), $NewDomain
        
        if ($CurrentMailNick -eq $NewMailNick) {
            Write-Host "  SKIP: No change needed" -ForegroundColor Yellow
            $SkippedCount++
            continue
        }

        Write-Host "  Current MailNickname: $CurrentMailNick" -ForegroundColor Gray
        Write-Host "  New MailNickname:     $NewMailNick" -ForegroundColor Green

        if ($RealMode) {
            try {
                Write-Host "  Updating MailNickname..." -ForegroundColor Yellow
                Update-MgUser -UserId $User.Id -MailNickname $NewMailNick -ErrorAction Stop
                Write-Host "  [SUCCESS] MailNickname updated successfully" -ForegroundColor Cyan
                
                # Verify the change
                Start-Sleep -Seconds 2
                $UpdatedUser = Get-MgUser -UserId $User.Id -Property "MailNickname" -ErrorAction Stop
                Write-Host "  [VERIFIED] New MailNickname: $($UpdatedUser.MailNickname)" -ForegroundColor White
                
                $UpdatedCount++
                
                # Log result
                $Results += [PSCustomObject]@{
                    ObjectId = $User.Id
                    DisplayName = $User.DisplayName
                    UserPrincipalName = $User.UserPrincipalName
                    OldMailNickname = $CurrentMailNick
                    NewMailNickname = $UpdatedUser.MailNickname
                    Status = "Success"
                    Error = ""
                }
                
            } catch {
                Write-Host "  [FAILED] MailNickname update failed: $($_.Exception.Message)" -ForegroundColor Red
                $ErrorCount++
                
                # Log error
                $Results += [PSCustomObject]@{
                    ObjectId = $User.Id
                    DisplayName = $User.DisplayName
                    UserPrincipalName = $User.UserPrincipalName
                    OldMailNickname = $CurrentMailNick
                    NewMailNickname = $NewMailNick
                    Status = "Failed"
                    Error = $_.Exception.Message
                }
            }
        } else {
            Write-Host "  [DRY RUN] No changes made" -ForegroundColor Yellow
            
            # Log dry run result
            $Results += [PSCustomObject]@{
                ObjectId = $User.Id
                DisplayName = $User.DisplayName
                UserPrincipalName = $User.UserPrincipalName
                OldMailNickname = $CurrentMailNick
                NewMailNickname = $NewMailNick
                Status = "DryRun"
                Error = ""
            }
        }
        
    } catch {
        Write-Warning "  Could not process user ${UserId}: $($_.Exception.Message)"
        $ErrorCount++
    }
}

# Display summary
Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
Write-Host "Total Processed: $ProcessedCount" -ForegroundColor White
Write-Host "Updated: $UpdatedCount" -ForegroundColor Green
Write-Host "Skipped: $SkippedCount" -ForegroundColor Yellow
Write-Host "Errors: $ErrorCount" -ForegroundColor Red

# Export results
if ($Results.Count -gt 0) {
    $ResultsPath = $CsvPath -replace '\.csv$', '_MailNickname_Results.csv'
    $Results | Export-Csv -Path $ResultsPath -NoTypeInformation
    Write-Host "`nResults exported to: $ResultsPath" -ForegroundColor Cyan
}

Write-Host "`nGuest MailNickname Update Script Complete." -ForegroundColor Magenta

# Disconnect from Graph
Disconnect-MgGraph | Out-Null