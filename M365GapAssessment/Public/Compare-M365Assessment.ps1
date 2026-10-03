function Compare-M365Assessment {
    <#
    .SYNOPSIS
        Compares two AssessmentFindings.json files (or assessment objects) and classifies each finding as New, Resolved, Changed or Unchanged.
    .DESCRIPTION
        Findings are keyed by FindingId. Only Gap status counts as "open": Pass, Accepted and NotAssessed are treated as not open.
          Accepted  - open in the baseline, now covered by an accepted-risk entry (not a fix)
          Reopened  - accepted in the baseline, open again now (acceptance expired or no longer covers it)
          New       - open now, not open (or absent) in the baseline
          Resolved  - open in the baseline, not open now
          Changed   - open in both, but severity or the set of affected objects differs (AddedObjects / RemovedObjects listed)
          Unchanged - open in both with the same severity and affected objects
        Affected objects are compared on the text before " - " or " (" so changing detail suffixes (dates, counts) do not register as changes.
    .EXAMPLE
        Compare-M365Assessment -Baseline .\Assessments\t_20260901-0900\AssessmentFindings.json -Current .\Assessments\t_20261001-0900\AssessmentFindings.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Baseline,
        [Parameter(Mandatory)][object]$Current
    )

    function Get-FindingSet($Source) {
        $data = if ($Source -is [string]) { Get-Content -Raw -LiteralPath $Source | ConvertFrom-Json } else { $Source }
        $set = @{}
        foreach ($f in @($data.Findings)) { $set[[string]$f.FindingId] = $f }
        $set
    }
    function Get-ObjectKey([string]$Text) { ($Text -split ' - | \(', 2)[0].Trim().ToLowerInvariant() }
    function Test-Open($F) { $null -ne $F -and $F.Status -eq 'Gap' }

    $before = Get-FindingSet $Baseline
    $after = Get-FindingSet $Current

    $ids = @($before.Keys) + @($after.Keys) | Sort-Object -Unique
    foreach ($id in $ids) {
        $b = $before[$id]; $a = $after[$id]
        $change = $null; $added = @(); $removed = @()

        if ($a.Status -eq 'Accepted' -and (Test-Open $b)) { $change = 'Accepted'; $removed = @($b.AffectedObjects) }
        elseif ($b.Status -eq 'Accepted' -and (Test-Open $a)) { $change = 'Reopened'; $added = @($a.AffectedObjects) }
        elseif ((Test-Open $a) -and -not (Test-Open $b)) { $change = 'New'; $added = @($a.AffectedObjects) }
        elseif ((Test-Open $b) -and -not (Test-Open $a)) { $change = 'Resolved'; $removed = @($b.AffectedObjects) }
        elseif ((Test-Open $a) -and (Test-Open $b)) {
            $bKeys = @($b.AffectedObjects | ForEach-Object { Get-ObjectKey $_ })
            $aKeys = @($a.AffectedObjects | ForEach-Object { Get-ObjectKey $_ })
            $added = @($a.AffectedObjects | Where-Object { (Get-ObjectKey $_) -notin $bKeys })
            $removed = @($b.AffectedObjects | Where-Object { (Get-ObjectKey $_) -notin $aKeys })
            $change = if ($added.Count -or $removed.Count -or $a.Severity -ne $b.Severity) { 'Changed' } else { 'Unchanged' }
        }
        if (-not $change) { continue }

        $src = if ($a) { $a } else { $b }
        [pscustomobject][ordered]@{
            FindingId       = $id
            Name            = $src.Name
            Change          = $change
            Severity        = $src.Severity
            PreviousSeverity = if ($b) { $b.Severity } else { $null }
            AddedObjects    = $added
            RemovedObjects  = $removed
        }
    }
}
