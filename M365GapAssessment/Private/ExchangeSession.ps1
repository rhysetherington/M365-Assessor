# Shared Exchange Online / Security & Compliance (Purview) sessions.
#
# Connect-ExchangeOnline and Connect-IPPSSession are interactive, so every extra connection is another sign-in for the person
# running the assessment. The Exchange-backed domains (ExchangeOnline, DefenderO365) therefore share one Exchange session, and
# Purview uses one compliance session; Invoke-M365SecurityReview closes both when a tenant is finished.

$script:ExchangeSessionOpen = $false
$script:ComplianceSessionOpen = $false

function Start-ExchangeSession {
    <#
    .SYNOPSIS
        Opens (or reuses) the Exchange Online session. Returns { Ready; Error }; never throws.
    #>
    [CmdletBinding()]
    param([string]$TenantId)

    if ($script:ExchangeSessionOpen) { return [pscustomobject]@{ Ready = $true; Error = $null } }
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        return [pscustomobject]@{ Ready = $false; Error = 'ExchangeOnlineManagement module is not installed (Install-Module ExchangeOnlineManagement -Scope CurrentUser).' }
    }
    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $conn = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($TenantId) { $conn.Organization = $TenantId }
        $exchangeCloud = (Get-CloudEnvironment).Exchange
        if ($exchangeCloud -ne 'O365Default') { $conn.ExchangeEnvironmentName = $exchangeCloud }
        Connect-ExchangeOnline @conn
        $script:ExchangeSessionOpen = $true
        [pscustomobject]@{ Ready = $true; Error = $null }
    }
    catch {
        [pscustomobject]@{ Ready = $false; Error = "Could not connect to Exchange Online: $((($_.Exception.Message -split '\r?\n')[0]))" }
    }
}

function Start-ComplianceSession {
    <#
    .SYNOPSIS
        Opens (or reuses) the Security & Compliance (Purview) session. Returns { Ready; Error }; never throws.
    #>
    [CmdletBinding()]
    param([string]$TenantId)

    if ($script:ComplianceSessionOpen) { return [pscustomobject]@{ Ready = $true; Error = $null } }
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        return [pscustomobject]@{ Ready = $false; Error = 'ExchangeOnlineManagement module is not installed (Install-Module ExchangeOnlineManagement -Scope CurrentUser).' }
    }
    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        $conn = @{ ShowBanner = $false; ErrorAction = 'Stop' }
        if ($TenantId) { $conn.Organization = $TenantId }
        $exchangeCloud = (Get-CloudEnvironment).Exchange
        if ($exchangeCloud -ne 'O365Default') { $conn.ExchangeEnvironmentName = $exchangeCloud }
        Connect-IPPSSession @conn
        $script:ComplianceSessionOpen = $true
        [pscustomobject]@{ Ready = $true; Error = $null }
    }
    catch {
        [pscustomobject]@{ Ready = $false; Error = "Could not connect to Security & Compliance (Purview): $((($_.Exception.Message -split '\r?\n')[0]))" }
    }
}

function Stop-ExchangeSessions {
    <#
    .SYNOPSIS
        Closes any Exchange / compliance session this module opened. Safe to call when nothing is open.
    #>
    [CmdletBinding()]
    param()
    if ($script:ExchangeSessionOpen -or $script:ComplianceSessionOpen) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    $script:ExchangeSessionOpen = $false
    $script:ComplianceSessionOpen = $false
}

function Assert-Cmdlet {
    # Throws a licence-aware message when a cmdlet is not available in the current session (typical when a licence is missing).
    param([Parameter(Mandatory)][string]$Name, [string]$Hint = 'the required licence may be missing')
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { throw "$Name is not available in this session ($Hint)." }
}
