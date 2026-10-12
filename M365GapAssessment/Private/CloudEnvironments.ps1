# One place that says how each Microsoft cloud is reached by every service the assessor talks to, so a run against a
# government or China tenant sends Graph, Exchange, Security & Compliance and Teams to the SAME cloud.
#
# LiveTested is $true only for clouds this module has actually been run against. The others are wired to the documented
# parameters but have never been run in a real tenant: they report themselves as such, and any endpoint a cloud does not offer
# surfaces as a NotAssessed finding rather than a wrong result.

$script:CloudEnvironmentName = 'Global'

$script:CloudEnvironments = [ordered]@{
    Global   = [pscustomobject]@{
        Name = 'Global'; Display = 'Microsoft 365 commercial (including GCC)'
        Exchange = 'O365Default'; TeamsSupported = $true; TeamsName = $null; LiveTested = $true
    }
    USGov    = [pscustomobject]@{
        Name = 'USGov'; Display = 'US Government GCC High'
        Exchange = 'O365USGovGCCHigh'; TeamsSupported = $true; TeamsName = 'TeamsGCCH'; LiveTested = $false
    }
    USGovDoD = [pscustomobject]@{
        Name = 'USGovDoD'; Display = 'US Government DoD'
        Exchange = 'O365USGovDoD'; TeamsSupported = $true; TeamsName = 'TeamsDOD'; LiveTested = $false
    }
    China    = [pscustomobject]@{
        Name = 'China'; Display = 'Microsoft 365 operated by 21Vianet (China)'
        Exchange = 'O365China'; TeamsSupported = $false; TeamsName = $null; LiveTested = $false
    }
}

function Get-CloudEnvironment {
    <#
    .SYNOPSIS
        The settings for a named cloud (Global, USGov, USGovDoD, China); defaults to the cloud of the current run.
    #>
    [CmdletBinding()]
    param([string]$Name = $script:CloudEnvironmentName)
    if ($Name -eq 'Germany') {
        throw "The 'Germany' cloud is not supported: Microsoft Cloud Germany was retired and its tenants moved to the commercial cloud (use -Environment Global)."
    }
    if (-not $script:CloudEnvironments.Contains($Name)) {
        throw "Unknown cloud environment '$Name'. Valid values: $($script:CloudEnvironments.Keys -join ', ')."
    }
    $script:CloudEnvironments[$Name]
}
