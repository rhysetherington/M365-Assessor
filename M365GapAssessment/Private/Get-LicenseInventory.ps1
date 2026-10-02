$script:LicenseDisplay = @{
    EntraP1         = 'Microsoft Entra ID P1'
    EntraP2         = 'Microsoft Entra ID P2'
    Intune          = 'Microsoft Intune'
    DefenderO365    = 'Defender for Office 365'
    DefenderEndpoint = 'Defender for Endpoint'
}

function Test-TenantCapability {
    # $true / $false when licensing is known, $null when the inventory could not be read.
    param([Parameter(Mandatory)][string]$Name)
    if ($null -eq $script:LicenseCapabilities) { return $null }
    [bool]$script:LicenseCapabilities[$Name]
}

function Get-LicenseInventory {
    <#
    .SYNOPSIS
        Reads subscribedSkus and derives which security capabilities the tenant is licensed for.
        Populates $script:LicenseCapabilities so later collectors can explain NotAssessed results.
    #>
    [CmdletBinding()]
    param()

    $skus = @(Get-GraphPagedResult -Uri '/v1.0/subscribedSkus')
    $active = @($skus | Where-Object { $_.capabilityStatus -eq 'Enabled' })
    $planNames = @($active | ForEach-Object { $_.servicePlans } | ForEach-Object { $_.servicePlanName } | Sort-Object -Unique)

    $has = { param([string[]]$names) [bool]@($planNames | Where-Object { $_ -in $names }).Count }
    $p2 = & $has 'AAD_PREMIUM_P2'
    $caps = @{
        EntraP2          = $p2
        EntraP1          = $p2 -or (& $has 'AAD_PREMIUM')   # P2 includes P1 features
        Intune           = (& $has 'INTUNE_A')
        DefenderO365     = (& $has 'ATP_ENTERPRISE', 'THREAT_INTELLIGENCE')
        DefenderEndpoint = (& $has 'WINDEFATP')
    }
    $script:LicenseCapabilities = $caps

    [pscustomobject][ordered]@{
        Capabilities = [pscustomobject][ordered]@{
            EntraP1          = $caps.EntraP1
            EntraP2          = $caps.EntraP2
            Intune           = $caps.Intune
            DefenderO365     = $caps.DefenderO365
            DefenderEndpoint = $caps.DefenderEndpoint
        }
        Skus         = @($active | ForEach-Object {
                [pscustomobject]@{ Sku = $_.skuPartNumber; Purchased = $_.prepaidUnits.enabled; Assigned = $_.consumedUnits }
            })
    }
}

function Get-LicenseGaps {
    [CmdletBinding()]
    param($Inventory)

    Invoke-Collector -Name 'Licensing' -FindingIds 'LIC-001' -Script {
        if (-not $Inventory) { throw 'License inventory could not be read (subscribedSkus).' }
        $skuText = ($Inventory.Skus | ForEach-Object { "$($_.Sku) ($($_.Assigned)/$($_.Purchased))" }) -join ', '
        $licensed = $Inventory.Capabilities.EntraP1
        New-Finding -Id 'LIC-001' -Status $(if ($licensed) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($skuText) { "Licensed SKUs (assigned/purchased): $skuText" } else { 'No active subscribed SKUs found.' })
    }
}
