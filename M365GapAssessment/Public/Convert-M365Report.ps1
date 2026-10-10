function Convert-M365Report {
    <#
    .SYNOPSIS
        Regenerates the HTML and/or Markdown report from a saved AssessmentFindings.json (no tenant connection needed).
    .DESCRIPTION
        Useful after the report design changes, or to re-brand an earlier run for a client. Writes next to the JSON file
        unless -OutputPath is given; the JSON itself is never modified.
    .EXAMPLE
        Convert-M365Report -Path .\Assessments\<run>\AssessmentFindings.json -ClientName 'Contoso Ltd' -BrandColor '#0a6cff' -LogoPath .\logo.png
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutputPath,
        [ValidateSet('HTML', 'Markdown')][string[]]$Format = @('HTML'),
        [string]$ClientName,
        [string]$AssessmentName,
        [string]$AssessorName,
        [string]$AssessmentDate,
        [string]$Reference,
        [string]$PreparedBy,
        [ValidatePattern('^#[0-9a-fA-F]{6}$')][string]$BrandColor,
        [string]$LogoPath,
        [switch]$HideTenantId
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "Findings file not found: $Path" }
    $assessment = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if (-not $assessment.Findings) { throw "'$Path' does not look like an AssessmentFindings.json file." }

    # Older runs predate the CIS mapping and the Accepted counter; fill them from the current mapping.
    foreach ($finding in $assessment.Findings) {
        if (-not $finding.PSObject.Properties['CisControl']) {
            $finding | Add-Member -NotePropertyName CisControl -NotePropertyValue @($script:ControlMapping[[string]$finding.FindingId].cis | Where-Object { $_ })
        }
    }
    if (-not $assessment.Summary.PSObject.Properties['Accepted']) {
        $assessment.Summary | Add-Member -NotePropertyName Accepted -NotePropertyValue @($assessment.Findings | Where-Object Status -eq 'Accepted').Count
    }

    # Optional overrides of the saved audit details (creates them for runs saved before metadata existed).
    if (-not $assessment.PSObject.Properties['Metadata'] -or -not $assessment.Metadata) {
        $assessment | Add-Member -NotePropertyName Metadata -NotePropertyValue ([pscustomobject]@{ ClientName = $null; AssessmentName = $null; AssessorName = $null; PreparedBy = $null; AssessmentDate = $null; Reference = $null }) -Force
    }
    foreach ($pair in @{ ClientName = $ClientName; AssessmentName = $AssessmentName; AssessorName = $AssessorName; AssessmentDate = $AssessmentDate; Reference = $Reference }.GetEnumerator()) {
        if ($pair.Value) { $assessment.Metadata | Add-Member -NotePropertyName $pair.Key -NotePropertyValue $pair.Value -Force }
    }
    if ($AssessmentDate) {
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParse($AssessmentDate, [ref]$parsed)) { throw "Assessment date '$AssessmentDate' is not a valid date (use yyyy-MM-dd)." }
        $assessment.Metadata.AssessmentDate = $parsed.ToString('yyyy-MM-dd')
    }
    $base = Get-AssessmentBaseName -Assessment $assessment

    $folder = if ($OutputPath) { $OutputPath } else { Split-Path -Parent (Resolve-Path -LiteralPath $Path) }
    $null = New-Item -ItemType Directory -Path $folder -Force
    $branding = @{ PreparedBy = $PreparedBy; BrandColor = $BrandColor; LogoPath = $LogoPath; HideTenantId = [bool]$HideTenantId }
    if ('HTML' -in $Format) {
        $p = Join-Path $folder $(if ($base) { "$base-Assessment.html" } else { 'M365_Security_Gap_Assessment.html' })
        New-AssessmentHtml -Assessment $assessment -Branding $branding | Set-Content -Path $p -Encoding utf8
        $p
    }
    if ('Markdown' -in $Format) {
        $p = Join-Path $folder $(if ($base) { "$base-Assessment.md" } else { 'M365_Security_Gap_Assessment.md' })
        New-AssessmentMarkdown -Assessment $assessment -Branding $branding | Set-Content -Path $p -Encoding utf8
        $p
    }
}
