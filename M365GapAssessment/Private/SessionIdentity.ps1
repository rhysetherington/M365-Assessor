# Which account each service really signed in as.
#
# Microsoft Graph, Exchange Online, Security & Compliance and Teams are separate sign-ins and some of them silently reuse a cached
# login, so a run billed as "Global Reader" could be answered by a more privileged account without anyone noticing. Each session
# registers the account it connected as; the report lists them and the run warns when they differ or cannot be determined.

$script:SessionIdentities = [ordered]@{}

function Register-SessionIdentity {
    <#
    .SYNOPSIS
        Records the account a service session signed in as ($null when it could not be determined).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Service, $Account)
    $script:SessionIdentities[$Service] = if ([string]::IsNullOrWhiteSpace([string]$Account)) { $null } else { [string]$Account }
}

function Get-SessionIdentityReport {
    <#
    .SYNOPSIS
        One row per registered session: Service, Account, and whether it matches the Microsoft Graph account
        (Yes / No / Unknown, or n/a when Graph used an app registration, which has no user to compare).
    #>
    [CmdletBinding()]
    param()
    $graph = $script:SessionIdentities['Microsoft Graph']
    $appOnly = $graph -and $graph -like 'app:*'
    foreach ($service in $script:SessionIdentities.Keys) {
        $account = $script:SessionIdentities[$service]
        $match = if ($service -eq 'Microsoft Graph') { 'Yes' }
        elseif (-not $account -or -not $graph) { 'Unknown' }
        elseif ($appOnly) { 'n/a' }
        elseif ($account -ieq $graph) { 'Yes' }
        else { 'No' }
        [pscustomobject][ordered]@{
            Service        = $service
            Account        = if ($account) { $account } else { 'unknown' }
            MatchesGraph   = $match
        }
    }
}

function Get-ExchangeSessionAccount {
    <#
    .SYNOPSIS
        The account of the Exchange Online or Security & Compliance session, from Get-ConnectionInformation; $null if unknown.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('Exchange', 'Compliance')][string]$Kind)
    try {
        $sessions = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object { "$($_.State)" -eq 'Connected' -or -not $_.State })
        if (-not $sessions.Count) { return $null }
        # The compliance (IPPS) endpoint host contains 'compliance'; the Exchange one does not. With a single session use it.
        $isCompliance = { param($s) "$($s.ConnectionUri)" -match 'compliance' }
        $pick = if ($sessions.Count -eq 1) { $sessions[0] }
        elseif ($Kind -eq 'Compliance') { $sessions | Where-Object { & $isCompliance $_ } | Select-Object -First 1 }
        else { $sessions | Where-Object { -not (& $isCompliance $_) } | Select-Object -First 1 }
        if ($pick -and $pick.UserPrincipalName) { [string]$pick.UserPrincipalName } else { $null }
    }
    catch { $null }
}

function Get-TeamsSessionAccount {
    <#
    .SYNOPSIS
        The account from a Connect-MicrosoftTeams result (Account.Id, or Account as a string); $null if unknown.
    #>
    [CmdletBinding()]
    param($Connection)
    if ($null -eq $Connection) { return $null }
    $account = $Connection.Account
    if ($null -eq $account) { return $null }
    if ($account.PSObject.Properties['Id'] -and $account.Id) { return [string]$account.Id }
    if ($account -is [string]) { return $account }
    $null
}
