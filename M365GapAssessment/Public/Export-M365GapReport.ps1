function Export-M365GapReport {
    <#
    .SYNOPSIS
        Writes AssessmentFindings.json (always) plus Markdown and/or HTML reports for an assessment object.
    .PARAMETER Assessment
        The assessment object returned by Invoke-M365SecurityReview. Accepts pipeline input.
    .PARAMETER ExportPath
        Folder to write the files to; it is created if needed.
    .PARAMETER Format
        JSON, Markdown and/or HTML. The JSON findings file is always written. Default: JSON and Markdown.
    .PARAMETER Branding
        Hashtable of report options: ClientName, PreparedBy, BrandColor (#RRGGBB), LogoPath (PNG, JPEG or SVG) and HideTenantId.
    .PARAMETER CisView
        Adds a section that regroups findings by CIS Microsoft 365 Foundations recommendation number and benchmark section.
    .PARAMETER IncludeEvidence
        Also writes evidence/<FindingId>.csv (the full list of affected items for each Gap finding) and evidence/_index.csv, and
        links them from the reports. Values are neutralised against spreadsheet formula injection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$Assessment,
        [Parameter(Mandatory)][string]$ExportPath,
        [ValidateSet('JSON', 'HTML', 'Markdown')][string[]]$Format = @('JSON', 'Markdown'),
        [hashtable]$Branding = @{},
        [switch]$IncludeEvidence,
        [switch]$CisView
    )

    process {
        try {
            $null = New-Item -ItemType Directory -Path $ExportPath -Force -ErrorAction Stop
            $written = [System.Collections.Generic.List[string]]::new()

            # Evidence first, so each finding carries its EvidenceFile path into the JSON and the reports.
            if ($IncludeEvidence) { foreach ($e in @(Write-EvidenceFiles -Assessment $Assessment -Folder $ExportPath)) { $written.Add($e) } }
            $Branding = @{} + $Branding
            $Branding.EvidenceRoot = $ExportPath
            if ($CisView) { $Branding.CisView = $true }

            $base = Get-AssessmentBaseName -Assessment $Assessment
            $jsonPath = Join-Path $ExportPath $(if ($base) { "$base-Findings.json" } else { 'AssessmentFindings.json' })
            $Assessment | Select-Object * -ExcludeProperty ExportedFiles | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding utf8
            $written.Add($jsonPath)

            if ('Markdown' -in $Format) {
                $p = Join-Path $ExportPath $(if ($base) { "$base-Assessment.md" } else { 'M365_Security_Gap_Assessment.md' })
                New-AssessmentMarkdown -Assessment $Assessment -Branding $Branding | Set-Content -Path $p -Encoding utf8
                $written.Add($p)
            }
            if ('HTML' -in $Format) {
                $p = Join-Path $ExportPath $(if ($base) { "$base-Assessment.html" } else { 'M365_Security_Gap_Assessment.html' })
                New-AssessmentHtml -Assessment $Assessment -Branding $Branding | Set-Content -Path $p -Encoding utf8
                $written.Add($p)
            }
            Protect-ExportPath -Path $ExportPath
            $written.ToArray()
        }
        catch { throw "Report export failed: $($_.Exception.Message)" }
    }
}
