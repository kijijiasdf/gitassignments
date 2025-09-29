<#
.SYNOPSIS
    Updates guest user MailNickname attribute only in Azure Entra ID using Microsoft Graph PowerShell.
.DESCRIPTION
    Processes a CSV of guest users and updates MailNickname to match the new Mail format.
.NOTES
    PowerShell 5.1 + Microsoft.Graph module required.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    [switch]$RealMode
)

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    Write-Error "Microsoft.Graph.Users module not found. Install with 'Install-Module Microsoft.Graph' (as Admin)."
    exit 1
}

Import-Module Microsoft.Graph.Users

$TenantId = Read-Host "Enter your Azure Tenant ID"
$SearchDomain = Read-Host "Enter the domain string to replace (e.g. pf-gt.com)"
$NewDomain = Read-Host "Enter the new domain string (e.g. pf.gt.com)"

try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "User.ReadWrite.All" -TenantId $TenantId -ErrorAction Stop
} catch {
    Write-Error "Could not connect to Microsoft Graph: $_"
    exit 1
}

$Users = Import-Csv -Path $CsvPath

foreach ($Row in $Users) {
    $Id = $Row.ObjectId
    if (-not $Id) { $Id = $Row.UserPrincipalName }
    if (-not $Id) { Write-Warning "No ObjectId or UPN found"; continue }

    try {
        $User = Get-MgUser -UserId $Id -Property "Id,UserPrincipalName,Mail,MailNickName,UserType"
        if ($User.UserType -ne "Guest") {
            Write-Host "Skipping (not guest): $($User.UserPrincipalName)" -ForegroundColor Yellow
            continue
        }
    } catch {
        Write-Warning "Could not find user $Id"
        continue
    }

    # Calculate what the new Mail should be (based on domain replacement)
    $CurrentMail = $User.Mail
    if ($CurrentMail -match "^(.*)@(.+)$") {
        $MailUser = $Matches[1]
        $MailDomain = $Matches[2] -replace [regex]::Escape($SearchDomain), $NewDomain
        $NewMail = "$MailUser@$MailDomain"
    } else {
        continue
    }

    $CurrentMailNick = $User.MailNickName
    $NewMailNick = $NewMail  # Set MailNickname to match new Mail

    Write-Host "`nGuest User: $($User.UserPrincipalName)" -ForegroundColor Green
    Write-Host "MailNickname Change: $CurrentMailNick --> $NewMailNick"

    if ($RealMode) {
        try {
            Write-Host "  Updating MailNickname..." -ForegroundColor Yellow
            Update-MgUser -UserId $User.Id -MailNickName $NewMailNick
            Write-Host "  [SUCCESS] MailNickname updated." -ForegroundColor Cyan
            
            Start-Sleep -Seconds 5
            $VerifyUser = Get-MgUser -UserId $User.Id -Property "MailNickName"
            Write-Host "  [VERIFIED] New MailNickname: $($VerifyUser.MailNickName)" -ForegroundColor White
            
        } catch {
            Write-Error "  [FAILED] MailNickname update failed: $_"
        }
    } else {
        Write-Host "  [DRY RUN] No changes made (test mode)." -ForegroundColor Yellow
    }
}

Write-Host "`nMailNickname Update Script Complete."