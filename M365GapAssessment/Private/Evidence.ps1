function ConvertTo-SafeCsvValue {
    <#
    .SYNOPSIS
        Makes a tenant-supplied string safe to put in a CSV that may be opened in Excel.
    .DESCRIPTION
        A value that starts with = + - @ (or a tab) is interpreted by spreadsheets as a formula, so a hostile display name such as
        =HYPERLINK("http://...") would run when the evidence file is opened. A leading apostrophe makes it plain text. Line breaks
        are flattened so one item stays on one row.
    #>
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return '' }
    $text = ([string]$Value) -replace '[\r\n]+', ' '
    if ($text -match '^[=+\-@\t]') { return "'$text" }
    $text
}

function Write-EvidenceFiles {
    <#
    .SYNOPSIS
        Writes one CSV per Gap finding that has affected items (evidence/<FindingId>.csv) plus evidence/_index.csv, and records each
        file's relative path on the finding as EvidenceFile so the reports can link to it.
    .DESCRIPTION
        The CSVs hold the full list of affected items (the reports show only the first 25). They contain no tenant ID. The item
        column is named AffectedItem, not Item, because (Import-Csv x).Item would otherwise hit PowerShell's array Item property.
        Returns the full paths written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Assessment,
        [Parameter(Mandatory)][string]$Folder
    )

    $written = [System.Collections.Generic.List[string]]::new()
    $index = [System.Collections.Generic.List[object]]::new()
    $withEvidence = @($Assessment.Findings | Where-Object { $_.Status -eq 'Gap' -and $_.AffectedCount -gt 0 })
    if (-not $withEvidence.Count) { return @() }

    $dir = Join-Path $Folder 'evidence'
    $null = New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop

    foreach ($f in $withEvidence) {
        $name = ConvertTo-SafeName -Text $f.FindingId -Fallback 'finding'
        $relative = "evidence/$name.csv"
        $path = Join-Path $Folder $relative
        @($f.AffectedObjects | ForEach-Object {
                [pscustomobject][ordered]@{ FindingId = $f.FindingId; Severity = $f.Severity; AffectedItem = ConvertTo-SafeCsvValue $_ }
            }) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8
        Add-Member -InputObject $f -NotePropertyName EvidenceFile -NotePropertyValue $relative -Force
        $written.Add($path)
        $index.Add([pscustomobject][ordered]@{
                FindingId     = $f.FindingId
                Name          = ConvertTo-SafeCsvValue $f.Name
                Severity      = $f.Severity
                AffectedCount = $f.AffectedCount
                File          = $relative
                ScfControl    = $f.ScfControl
                NistCsf       = $f.NistCsf
                CisControl    = ConvertTo-SafeCsvValue (@($f.CisControl) -join '; ')
                Detail        = ConvertTo-SafeCsvValue $f.Detail
            })
    }

    $indexPath = Join-Path $dir '_index.csv'
    $index | Export-Csv -LiteralPath $indexPath -NoTypeInformation -Encoding utf8
    $written.Add($indexPath)
    $written.ToArray()
}

function Get-EvidenceLink {
    <#
    .SYNOPSIS
        The relative evidence path for a finding, or $null when there is none or the file is not next to the report being written.
    #>
    [CmdletBinding()]
    param($Finding, [hashtable]$Branding = @{})
    if (-not $Finding.EvidenceFile) { return $null }
    if ($Branding.EvidenceRoot -and -not (Test-Path -LiteralPath (Join-Path $Branding.EvidenceRoot $Finding.EvidenceFile))) { return $null }
    [string]$Finding.EvidenceFile
}
