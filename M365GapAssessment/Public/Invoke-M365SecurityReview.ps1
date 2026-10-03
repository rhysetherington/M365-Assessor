function Invoke-M365SecurityReview {
    <#
    .SYNOPSIS
        Runs the full read-only assessment (Entra ID, Defender, Secure Score) for one or more tenants and exports reports.
    .EXAMPLE
        Invoke-M365SecurityReview -TenantId contoso.onmicrosoft.com -Format JSON,Markdown,HTML
    .EXAMPLE
        'tenantA.onmicrosoft.com','tenantB.onmicrosoft.com' | ForEach-Object { Invoke-M365SecurityReview -TenantId $_ -UseDeviceAuthentication }
    #>
    [CmdletBinding()]
    param(
        [string[]]$TenantId,
        [string]$ExportPath = (Join-Path (Get-Location) 'M365Assessment'),
        [ValidateSet('JSON', 'HTML', 'Markdown')][string[]]$Format = @('JSON', 'Markdown'),
        [pscredential]$Credential,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [switch]$UseDeviceAuthentication,
        [ValidateSet('Licensing', 'EntraID', 'EntraPolicy', 'Defender', 'SecureScore', 'EmailDns', 'ExchangeOnline', 'Teams')]
        [string[]]$Domain = @('Licensing', 'EntraID', 'EntraPolicy', 'Defender', 'SecureScore', 'EmailDns'),
        [string]$DohEndpoint = 'https://cloudflare-dns.com/dns-query',
        [int]$StaleDays = 90,
        [int]$SecretWarningDays = 30,
        [int]$TargetScorePercent = 70,
        [string]$AcceptedRiskPath,
        [string]$ClientName,
        [string]$PreparedBy,
        [ValidatePattern('^#[0-9a-fA-F]{6}$')][string]$BrandColor,
        [string]$LogoPath,
        [switch]$SkipRoleCheck,
        [switch]$NoExport
    )

    # A $null entry means "reuse the current Graph session / default tenant"; the comma keeps it from unrolling to nothing.
    $tenants = @(if ($TenantId) { $TenantId } else { , $null })
    $tenantIndex = 0

    foreach ($tenant in $tenants) {
        $tenantIndex++
        $base = [int](($tenantIndex - 1) / $tenants.Count * 100)
        $label = if ($tenant) { $tenant } else { 'current session' }
        Write-Progress -Id 1 -Activity "M365 Gap Assessment [$label]" -Status 'Connecting' -PercentComplete $base

        # --- Connect -------------------------------------------------------------------------
        $connect = @{ SkipRoleCheck = $SkipRoleCheck }
        if ($tenant) { $connect.TenantId = $tenant }
        if ($Credential) { $connect.Credential = $Credential }
        if ($CertificateThumbprint) { $connect.CertificateThumbprint = $CertificateThumbprint; $connect.ClientId = $ClientId }
        if ($UseDeviceAuthentication -and -not $Credential -and -not $CertificateThumbprint) { $connect.UseDeviceAuthentication = $true }
        $context = Connect-M365Assessment @connect

        # --- Collect -------------------------------------------------------------------------
        $findings = [System.Collections.Generic.List[object]]::new()

        # Licensing is always read first (when possible) so later NotAssessed results can be explained by missing licences.
        $script:LicenseCapabilities = $null
        $licensing = $null
        try { $licensing = Get-LicenseInventory }
        catch { Write-Warning "License inventory unavailable: $($_.Exception.Message)" }

        $steps = @($Domain).Count
        $done = 0
        foreach ($d in $Domain) {
            $pct = $base + [int](($done / $steps) * (100 / $tenants.Count) * 0.9)
            Write-Progress -Id 1 -Activity "M365 Gap Assessment [$($context.TenantId)]" -Status "Collecting: $d" -PercentComplete $pct
            $result = switch ($d) {
                'Licensing' { Get-LicenseGaps -Inventory $licensing }
                'EntraID' { Get-EntraIDGaps -StaleDays $StaleDays -SecretWarningDays $SecretWarningDays }
                'EntraPolicy' { Get-EntraPolicyGaps -StaleDays $StaleDays }
                'Defender' { Get-DefenderGaps }
                'SecureScore' { Get-SecureScoreGaps -TargetScorePercent $TargetScorePercent }
                'EmailDns' { Get-EmailDnsGaps -DohEndpoint $DohEndpoint }
                'ExchangeOnline' { Get-ExchangeOnlineGaps -TenantId $tenant }
                'Teams' { Get-TeamsGaps -TenantId $tenant }
            }
            foreach ($f in @($result)) { if ($f) { $findings.Add($f) } }
            $done++
        }

        Set-AcceptedRisk -Findings $findings -Risks @(Import-AcceptedRisk -Path $AcceptedRiskPath)
        $ordered = @($findings | Sort-Object @{ Expression = { $script:SeverityOrder[[string]$_.Severity] } }, FindingId)
        $gapList = @($ordered | Where-Object Status -eq 'Gap')

        $tenantName = $null
        try { $tenantName = (Invoke-GraphRequestWithRetry -Uri '/v1.0/organization?$select=displayName').value[0].displayName } catch { }

        $assessment = [pscustomobject][ordered]@{
            TenantId      = $context.TenantId
            TenantName    = $tenantName
            AssessedAt    = [datetime]::UtcNow
            AssessedBy    = $context.Account
            ModuleVersion = (Get-Module M365GapAssessment).Version.ToString()
            Domains       = $Domain
            Licensing     = $licensing
            Score         = Measure-AssessmentScore -Findings $ordered
            Summary       = [pscustomobject][ordered]@{
                TotalChecks  = $ordered.Count
                Gaps         = $gapList.Count
                Passed       = @($ordered | Where-Object Status -eq 'Pass').Count
                NotAssessed  = @($ordered | Where-Object Status -eq 'NotAssessed').Count
                Accepted     = @($ordered | Where-Object Status -eq 'Accepted').Count
                GapsBySeverity = [pscustomobject][ordered]@{
                    Critical = @($gapList | Where-Object Severity -eq 'Critical').Count
                    High     = @($gapList | Where-Object Severity -eq 'High').Count
                    Medium   = @($gapList | Where-Object Severity -eq 'Medium').Count
                    Low      = @($gapList | Where-Object Severity -eq 'Low').Count
                }
            }
            Findings      = $ordered
            ExportedFiles = @()
        }

        $branding = @{ ClientName = $ClientName; PreparedBy = $PreparedBy; BrandColor = $BrandColor; LogoPath = $LogoPath }
        # --- Export --------------------------------------------------------------------------
        if (-not $NoExport) {
            Write-Progress -Id 1 -Activity "M365 Gap Assessment [$($context.TenantId)]" -Status 'Exporting reports' -PercentComplete ($base + 95 / $tenants.Count)
            $folder = Join-Path $ExportPath ("{0}_{1}" -f $context.TenantId, (Get-Date -Format 'yyyyMMdd-HHmm'))
            $assessment.ExportedFiles = @(Export-M365GapReport -Assessment $assessment -ExportPath $folder -Format $Format -Branding $branding)
        }
        $assessment
    }
    Write-Progress -Id 1 -Activity 'M365 Gap Assessment' -Completed
}
