<#
.SYNOPSIS
    Grants one app registration a role on named sites, for a Sites.Selected run.

.DESCRIPTION
    Sites.Selected consent grants nothing on its own. Each site has to be granted separately, and the
    grant is a POST per site. This script does that, and then reads each grant back.

    The read-back is not decoration. What this script writes and what the tenant holds are two
    different things, and the second is the one the measurement depends on - so the grant is printed
    from the service's own reply rather than from the fact that a POST returned 201.

    Sites named but not passed a role are left alone and reported as left alone. That is how the
    ungranted site in the design gets to be ungranted: by never appearing here, or by appearing with
    no role. Silence about it would be indistinguishable from forgetting it.

.NOTES
    Needs Microsoft.Graph.Authentication and an account that can consent to Sites.FullControl.All.
    That grant belongs to the person running this, not to the app being measured - the app under test
    must hold Sites.Selected and nothing wider, or every site answers and the run measures that.

.EXAMPLE
    ./grant-sites-selected.ps1 `
        -AppId 00000000-0000-0000-0000-000000000000 `
        -AppName capability-inventory `
        -Grant @{ 'https://contoso.sharepoint.com/sites/one' = 'read'
                  'https://contoso.sharepoint.com/sites/two' = 'fullcontrol' } `
        -LeaveAlone 'https://contoso.sharepoint.com/sites/three'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $AppId,
    [Parameter(Mandatory)] [string] $AppName,

    # Site URL -> role. 'read', 'write', 'owner', 'fullcontrol', or several separated by commas.
    [Parameter(Mandatory)] [hashtable] $Grant,

    # Sites deliberately left ungranted. Named so the report can say they were a choice.
    [string[]] $LeaveAlone = @()
)

$ErrorActionPreference = 'Stop'

Import-Module Microsoft.Graph.Authentication
Connect-MgGraph -Scopes 'Sites.FullControl.All' -NoWelcome

function Resolve-SiteId([string] $url) {
    $uri = [uri] $url
    $path = $uri.AbsolutePath.TrimEnd('/')
    (Invoke-MgGraphRequest -Method GET -Uri "v1.0/sites/$($uri.Host):$path").id
}

function Show-Grants([string] $siteId, [string] $url) {
    $held = (Invoke-MgGraphRequest -Method GET -Uri "v1.0/sites/$siteId/permissions").value

    if (-not $held) {
        Write-Host "    the site holds no app grants at all" -ForegroundColor DarkGray
        return
    }

    foreach ($p in $held) {
        $who = ($p.grantedToIdentitiesV2 | ForEach-Object { $_.application.displayName }) -join ', '
        Write-Host "    $($p.roles -join '+')  ->  $who" -ForegroundColor DarkGray
    }
}

foreach ($url in $Grant.Keys) {
    $roles = @($Grant[$url] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

    Write-Host "$url" -ForegroundColor Cyan
    $siteId = Resolve-SiteId $url

    $body = @{
        roles               = $roles
        grantedToIdentities = @(@{ application = @{ id = $AppId; displayName = $AppName } })
    }

    Invoke-MgGraphRequest -Method POST -Uri "v1.0/sites/$siteId/permissions" -Body ($body | ConvertTo-Json -Depth 5) | Out-Null
    Write-Host "  granted $($roles -join '+')" -ForegroundColor Green

    # Read back rather than trust the write. The run downstream depends on what the tenant holds.
    Write-Host "  the site now reports:"
    Show-Grants $siteId $url
}

foreach ($url in $LeaveAlone) {
    Write-Host "$url" -ForegroundColor Cyan
    Write-Host "  left ungranted on purpose" -ForegroundColor Yellow

    # Read it anyway. "I did not grant it" and "it holds no grant" are different claims, and only the
    # second one is a fact about the tenant.
    Show-Grants (Resolve-SiteId $url) $url
}

Write-Host ""
Write-Host "Put at least one file in every site, including the ungranted one." -ForegroundColor Yellow
Write-Host "An empty library and an empty answer are the same shape until a site known to have"
Write-Host "files answers the same call."
