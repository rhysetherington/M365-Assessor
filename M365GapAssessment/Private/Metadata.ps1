function ConvertTo-SafeName {
    <#
    .SYNOPSIS
        Turns free text into a file/folder-safe token (letters, digits, dash). Used for ClientName-Date names so user input can
        never add path separators or traversal.
    #>
    [CmdletBinding()]
    param([string]$Text, [string]$Fallback = 'Assessment')
    $clean = (($Text -replace '[^\p{L}\p{Nd}]+', '-').Trim('-'))
    if ($clean.Length -gt 60) { $clean = $clean.Substring(0, 60).Trim('-') }
    if ($clean) { $clean } else { $Fallback }
}

function Get-DefaultClientName {
    <#
    .SYNOPSIS
        Best-guess client name when none is given: the first label of the primary domain (contoso.com -> contoso),
        preferring a custom verified domain over *.onmicrosoft.com, then the tenant display name.
    #>
    [CmdletBinding()]
    param([string]$PrimaryDomain, [string]$TenantDisplayName)
    if ($PrimaryDomain) { return ($PrimaryDomain -split '\.')[0] }
    if ($TenantDisplayName) { return $TenantDisplayName }
    'Client'
}

function Read-MetadataValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Prompt, [string]$Default)
    $suffix = if ($Default) { " [$Default]" } else { '' }
    $answer = Read-Host "$Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { $Default } else { $answer.Trim() }
}

function Resolve-AssessmentMetadata {
    <#
    .SYNOPSIS
        Collects the audit artefacts for a run (client, assessment name, assessor, date, reference). Anything not supplied is asked
        for interactively with a sensible default; use -NoPrompt (or a non-interactive session) to accept defaults silently.
    #>
    [CmdletBinding()]
    param(
        [string]$ClientName,
        [string]$AssessmentName,
        [string]$AssessorName,
        [string]$PreparedBy,
        [string]$AssessmentDate,
        [string]$Reference,
        [string]$TenantDisplayName,
        [string]$PrimaryDomain,
        [string]$SignedInAccount,
        [switch]$NoPrompt
    )

    $interactive = [Environment]::UserInteractive -and -not $NoPrompt
    $clip = { param($t, $max) $v = ([string]$t -replace '[\x00-\x1f]', ' ').Trim(); if ($v.Length -gt $max) { $v.Substring(0, $max) } else { $v } }

    if ($interactive) {
        Write-Host ''
        Write-Host 'Assessment details (press Enter to accept the value in brackets)' -ForegroundColor Cyan
    }
    $defaultClient = Get-DefaultClientName -PrimaryDomain $PrimaryDomain -TenantDisplayName $TenantDisplayName
    if (-not $ClientName) { $ClientName = if ($interactive) { Read-MetadataValue 'Client name' $defaultClient } else { $defaultClient } }
    if (-not $AssessmentName) { $AssessmentName = if ($interactive) { Read-MetadataValue 'Assessment name' 'Microsoft 365 Security Gap Assessment' } else { 'Microsoft 365 Security Gap Assessment' } }
    if (-not $AssessorName) { $AssessorName = if ($interactive) { Read-MetadataValue 'Assessor (who is performing this assessment)' $SignedInAccount } else { $SignedInAccount } }
    $today = (Get-Date).ToString('yyyy-MM-dd')
    if (-not $AssessmentDate) { $AssessmentDate = if ($interactive) { Read-MetadataValue 'Assessment date (yyyy-MM-dd)' $today } else { $today } }
    if (-not $Reference -and $interactive) { $Reference = Read-MetadataValue 'Engagement / reference number (optional)' '' }

    $parsed = [datetime]::MinValue
    if (-not [datetime]::TryParse($AssessmentDate, [ref]$parsed)) { throw "Assessment date '$AssessmentDate' is not a valid date (use yyyy-MM-dd)." }

    [pscustomobject][ordered]@{
        ClientName        = & $clip $ClientName 120
        AssessmentName    = & $clip $AssessmentName 120
        AssessorName      = & $clip $AssessorName 120
        PreparedBy        = & $clip $PreparedBy 120
        AssessmentDate    = $parsed.ToString('yyyy-MM-dd')
        Reference         = & $clip $Reference 60
        TenantDisplayName = & $clip $TenantDisplayName 120
        PrimaryDomain     = & $clip $PrimaryDomain 253
    }
}

function Get-AssessmentBaseName {
    <#
    .SYNOPSIS
        ClientName-Date, e.g. contoso-2026-10-03. Falls back to the legacy name when a saved assessment has no metadata.
    #>
    [CmdletBinding()]
    param($Assessment)
    $m = $Assessment.Metadata
    if ($m -and $m.ClientName -and $m.AssessmentDate) { return ('{0}-{1}' -f (ConvertTo-SafeName $m.ClientName), $m.AssessmentDate) }
    $null
}
