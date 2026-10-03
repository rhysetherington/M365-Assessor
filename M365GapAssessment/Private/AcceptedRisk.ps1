function Import-AcceptedRisk {
    <#
    .SYNOPSIS
        Loads a per-tenant accepted-risk file (JSON). Returns an empty list when no path is given.
    .DESCRIPTION
        Expected shape:
        { "risks": [ { "findingId": "ENT-USR-001", "affected": ["breakglass1@contoso.com - Global Administrator"],
                       "reason": "Break-glass account", "approvedBy": "J. Smith", "expires": "2027-01-31" } ] }
        "affected" and "expires" are optional.
    #>
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) { return @() }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Accepted-risk file not found: $Path" }
    $risks = @((Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json).risks)
    foreach ($r in $risks) {
        if (-not $r.findingId -or -not $r.reason) { throw "Accepted-risk entries need 'findingId' and 'reason' ($Path)." }
    }
    $risks
}

function Test-AcceptedRisk {
    <#
    .SYNOPSIS
        Decides whether one accepted-risk entry covers a Gap finding. Returns $true only if the whole gap is covered.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Finding,
        [Parameter(Mandatory)][object]$Risk
    )

    if ($Risk.findingId -ne $Finding.FindingId) { return $false }

    # An expired acceptance stops applying so the gap resurfaces for re-approval.
    if ($Risk.expires) {
        $expires = [datetime]::MinValue
        if (-not [datetime]::TryParse([string]$Risk.expires, [ref]$expires)) { return $false }
        if ($expires.Date -lt [datetime]::UtcNow.Date) { return $false }
    }

    # No 'affected' list means the whole finding is accepted.
    $accepted = @($Risk.affected | Where-Object { $_ })
    if (-not $accepted.Count) { return $true }

    # Every affected object must be covered, otherwise a new object would be hidden by an old acceptance.
    # Prefix match tolerates detail suffixes that change between runs ("user - role (last sign-in ...)").
    $affected = @($Finding.AffectedObjects)
    if (-not $affected.Count) { return $false }
    foreach ($obj in $affected) {
        $covered = $accepted | Where-Object { ([string]$obj).StartsWith([string]$_, [System.StringComparison]::OrdinalIgnoreCase) }
        if (-not $covered) { return $false }
    }
    return $true
}

function Set-AcceptedRisk {
    <#
    .SYNOPSIS
        Marks Gap findings covered by an accepted-risk entry as Status = 'Accepted' and records who/why.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Findings,
        [object[]]$Risks = @()
    )

    foreach ($f in $Findings) {
        if ($f.Status -ne 'Gap') { continue }
        $hit = $Risks | Where-Object { $_.findingId -eq $f.FindingId -and (Test-AcceptedRisk -Finding $f -Risk $_) } | Select-Object -First 1
        if ($hit) {
            $f.Status = 'Accepted'
            $f | Add-Member -NotePropertyName AcceptedRisk -NotePropertyValue ([pscustomobject]@{
                    Reason = $hit.reason; ApprovedBy = $hit.approvedBy; Expires = $hit.expires
                }) -Force
        }
    }
}
