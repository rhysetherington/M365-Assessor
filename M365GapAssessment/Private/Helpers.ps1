function Get-GraphErrorSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$ErrorRecord)

    $code = $null
    try { $code = [int]$ErrorRecord.Exception.Response.StatusCode } catch { }
    $message = $ErrorRecord.Exception.Message
    if ($ErrorRecord.ErrorDetails.Message) {
        # The SDK prefixes the JSON body with the raw HTTP status line and headers; parse from the first brace.
        try {
            $raw = [string]$ErrorRecord.ErrorDetails.Message
            $start = $raw.IndexOf('{')
            if ($start -ge 0) {
                $parsed = ($raw.Substring($start) | ConvertFrom-Json).error.message
                if ($parsed) { $message = $parsed }
            }
        }
        catch { }
    }
    [pscustomobject]@{ StatusCode = $code; Message = $message }
}

function Invoke-GraphRequestWithRetry {
    <#
    .SYNOPSIS
        Invoke-MgGraphRequest with retry/backoff for throttling (429) and transient (502/503/504) errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [int]$MaxRetries = 5
    )

    $attempt = 0
    while ($true) {
        try {
            $params = @{ Method = 'GET'; Uri = $Uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
            if ($Headers) { $params.Headers = $Headers }
            return Invoke-MgGraphRequest @params
        }
        catch {
            $err = $_
            $info = Get-GraphErrorSummary -ErrorRecord $err
            $transient = $info.StatusCode -in 429, 502, 503, 504
            if (-not $transient -or $attempt -ge $MaxRetries) { throw $err }

            $attempt++
            $delay = [math]::Pow(2, $attempt)
            try {
                $retryAfter = $err.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                if ($retryAfter) { $delay = [math]::Max($delay, $retryAfter) }
            }
            catch { }
            Write-Verbose "Graph returned $($info.StatusCode) for $Uri; retry $attempt/$MaxRetries in ${delay}s"
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-GraphPagedResult {
    <#
    .SYNOPSIS
        Follows @odata.nextLink until exhausted (or MaxItems reached) and returns all items.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [int]$MaxItems = 0
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $response = Invoke-GraphRequestWithRetry -Uri $next -Headers $Headers
        if ($null -ne $response.value) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        elseif ($null -ne $response -and $null -eq $response.'@odata.context') {
            $results.Add($response)
        }
        if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) { break }
        $next = $response.'@odata.nextLink'
    }
    Write-Verbose "Retrieved $($results.Count) item(s) from $Uri"
    $results.ToArray()
}

function Test-HasItems {
    # @($null).Count is 1 in PowerShell, so null-safe emptiness needs its own helper.
    param($Value)
    @($Value | Where-Object { $null -ne $_ }).Count -gt 0
}

function New-Finding {
    <#
    .SYNOPSIS
        Builds a finding object and enriches it from ControlMapping.json (severity, SCF, NIST CSF, remediation).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [ValidateSet('Gap', 'Pass', 'NotAssessed', 'Accepted')][string]$Status = 'Gap',
        [object[]]$AffectedObjects = @(),
        [string]$Detail = '',
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')][string]$Severity
    )

    $map = $script:ControlMapping[$Id]
    if (-not $map) { Write-Warning "No ControlMapping.json entry for finding '$Id'." }
    $affected = @($AffectedObjects | Where-Object { $null -ne $_ })

    # Explain NotAssessed results caused by missing licences, so "unlicensed" is distinguishable from "misconfigured".
    if ($Status -eq 'NotAssessed' -and $map.license -and ((Test-TenantCapability -Name $map.license) -eq $false)) {
        $Detail = "Tenant has no $($script:LicenseDisplay[$map.license]) licence. $Detail".Trim()
    }

    [pscustomobject][ordered]@{
        FindingId       = $Id
        Name            = $map.name
        Domain          = $map.domain
        Severity        = if ($Severity) { $Severity } else { $map.severity }
        Status          = $Status
        AffectedCount   = $affected.Count
        AffectedObjects = $affected
        Detail          = $Detail
        ScfControl      = $map.scf
        NistCsf         = $map.nistCsf
        Remediation     = @($map.remediation)
    }
}

function Invoke-Collector {
    <#
    .SYNOPSIS
        Runs one check. Any failure (403 licence/permission, schema change, outage) becomes NotAssessed findings
        instead of aborting the whole assessment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$FindingIds,
        [Parameter(Mandatory)][scriptblock]$Script
    )

    try {
        & $Script
    }
    catch {
        $err = $_
        $info = Get-GraphErrorSummary -ErrorRecord $err
        $hint = switch ($info.StatusCode) {
            401 { 'Token rejected - reconnect.' }
            403 { 'Missing permission or licence (Entra ID P1/P2, Intune, Defender) for this data.' }
            default { '' }
        }
        $detail = ("$($info.Message) $hint").Trim()
        Write-Warning "[$Name] not assessed: $detail"
        foreach ($id in $FindingIds) { New-Finding -Id $id -Status NotAssessed -Detail $detail }
    }
}

function Measure-AssessmentScore {
    <#
    .SYNOPSIS
        Converts findings into a single 0-100 compliance score for the executive summary.
    .DESCRIPTION
        Receives every finding (Status = Gap | Pass | NotAssessed; Severity = Critical | High | Medium | Low | Informational).
        Return a [double] percentage, or $null if there is nothing meaningful to score.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Findings)

    # Per-finding scoring: each check counts once, weighted by severity. AffectedCount is reported on the
    # finding itself but deliberately does not influence the score. NotAssessed counts as a failure so
    # unverifiable controls surface for review (a compensating control may exist elsewhere).
    $weights = @{ Critical = 10; High = 5; Medium = 3; Low = 1 }

    $scored = @($Findings | Where-Object { $weights.ContainsKey([string]$_.Severity) })
    if (-not $scored.Count) { return $null }

    $total  = ($scored | ForEach-Object { $weights[[string]$_.Severity] } | Measure-Object -Sum).Sum
    $passed = ($scored | Where-Object { $_.Status -in 'Pass', 'Accepted' } | ForEach-Object { $weights[[string]$_.Severity] } | Measure-Object -Sum).Sum

    [math]::Round(100 * ($passed / $total), 1)
}
