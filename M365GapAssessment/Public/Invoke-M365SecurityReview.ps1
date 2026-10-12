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
        [ValidateScript({ if (Test-TenantIdentifier $_) { $true } else { throw "'$_' is not a tenant GUID or a domain name." } })]
        [string[]]$TenantId,
        [string]$ExportPath = (Join-Path (Get-Location) 'M365Assessment'),
        [ValidateSet('JSON', 'HTML', 'Markdown')][string[]]$Format = @('JSON', 'Markdown'),
        [pscredential]$Credential,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [switch]$UseDeviceAuthentication,
        [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')][string]$Environment = 'Global',
        [ValidateSet('Licensing', 'EntraID', 'EntraPolicy', 'Defender', 'SecureScore', 'EmailDns', 'ExchangeOnline', 'DefenderO365', 'Purview', 'Teams', 'SharePoint')]
        [string[]]$Domain = @('Licensing', 'EntraID', 'EntraPolicy', 'Defender', 'SecureScore', 'EmailDns', 'SharePoint'),
        [string]$DohEndpoint = 'https://cloudflare-dns.com/dns-query',
        [int]$StaleDays = 90,
        [int]$SecretWarningDays = 30,
        [int]$TargetScorePercent = 70,
        [string]$AcceptedRiskPath,
        [string]$ClientName,
        [string]$AssessmentName,
        [string]$AssessorName,
        [string]$AssessmentDate,
        [string]$Reference,
        [switch]$NoPrompt,
        [string]$PreparedBy,
        [ValidatePattern('^#[0-9a-fA-F]{6}$')][string]$BrandColor,
        [string]$LogoPath,
        [switch]$HideTenantId,
        [switch]$IncludeEvidence,
        [switch]$CisView,
        [switch]$SkipRoleCheck,
        [switch]$NoExport
    )

    # No tenant is stored in the module or in scripts: prompt when it was not supplied.
    $tenants = @(if ($TenantId) { $TenantId } else { Read-TenantIdentifier })
    $tenantIndex = 0

    foreach ($tenant in $tenants) {
        $tenantIndex++
        $base = [int](($tenantIndex - 1) / $tenants.Count * 100)
        $label = $tenant
        Write-Progress -Id 1 -Activity "M365 Gap Assessment [$label]" -Status 'Connecting' -PercentComplete $base

        # --- Connect -------------------------------------------------------------------------
        $connect = @{ SkipRoleCheck = $SkipRoleCheck; Environment = $Environment }
        if ($tenant) { $connect.TenantId = $tenant }
        if ($Credential) { $connect.Credential = $Credential }
        if ($CertificateThumbprint) { $connect.CertificateThumbprint = $CertificateThumbprint; $connect.ClientId = $ClientId }
        if ($UseDeviceAuthentication -and -not $Credential -and -not $CertificateThumbprint) { $connect.UseDeviceAuthentication = $true }
        $context = Connect-M365Assessment @connect

        # --- Assessment details (client, assessor, date): asked before the long collection starts ----------------
        Write-Progress -Id 1 -Activity "M365 Gap Assessment [$label]" -Completed
        $tenantName = $null
        $primaryDomain = $null
        try {
            $org = (Invoke-GraphRequestWithRetry -Uri '/v1.0/organization?$select=displayName,verifiedDomains').value[0]
            $tenantName = $org.displayName
            $custom = @($org.verifiedDomains | Where-Object { $_.name -notlike '*.onmicrosoft.com' -and $_.name -notlike '*.mail.onmicrosoft.com' })
            $default = $org.verifiedDomains | Where-Object isDefault | Select-Object -First 1
            $primaryDomain = if ($default -and $default.name -notlike '*.onmicrosoft.com') { $default.name } elseif ($custom.Count) { $custom[0].name } elseif ($default) { $default.name }
        }
        catch { }
        $metadata = Resolve-AssessmentMetadata -ClientName $ClientName -AssessmentName $AssessmentName -AssessorName $AssessorName `
            -PreparedBy $PreparedBy -AssessmentDate $AssessmentDate -Reference $Reference -TenantDisplayName $tenantName `
            -PrimaryDomain $primaryDomain -SignedInAccount $context.Account -NoPrompt:$NoPrompt


        # --- Collect -------------------------------------------------------------------------
        $findings = [System.Collections.Generic.List[object]]::new()

        # Licensing is always read first (when possible) so later NotAssessed results can be explained by missing licences.
        $script:LicenseCapabilities = $null
        Reset-CollectorCache
        Register-SessionIdentity -Service 'Microsoft Graph' -Account $context.Account
        $licensing = $null
        try { $licensing = Get-LicenseInventory }
        catch { Write-Warning "License inventory unavailable: $($_.Exception.Message)" }

        $steps = @($Domain).Count
        $done = 0
        # Exchange / Purview sessions are shared between domains and always closed when this tenant is finished.
        try {
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
                    'DefenderO365' { Get-DefenderO365Gaps -TenantId $tenant }
                    'Purview' { Get-PurviewGaps -TenantId $tenant }
                    'Teams' { Get-TeamsGaps -TenantId $tenant }
                    'SharePoint' { Get-SharePointGaps }
                }
                foreach ($f in @($result)) { if ($f) { $findings.Add($f) } }
                $done++
            }
        }
        finally { Stop-ExchangeSessions }

        # Report which account each service used, and say so when they differ or could not be determined.
        $sessions = @(Get-SessionIdentityReport)
        foreach ($s in $sessions) {
            if ($s.MatchesGraph -eq 'No') { Write-Warning "$($s.Service) signed in as '$($s.Account)' but Microsoft Graph as '$($context.Account)'. Results from the two may reflect different permissions." }
            elseif ($s.MatchesGraph -eq 'Unknown') { Write-Warning "Could not determine which account $($s.Service) signed in as; confirm it used the intended (read-only) account." }
        }

        Set-AcceptedRisk -Findings $findings -Risks @(Import-AcceptedRisk -Path $AcceptedRiskPath)
        $ordered = @($findings | Sort-Object @{ Expression = { $script:SeverityOrder[[string]$_.Severity] } }, FindingId)
        $gapList = @($ordered | Where-Object Status -eq 'Gap')

        $assessment = [pscustomobject][ordered]@{
            TenantId      = $context.TenantId
            TenantName    = $tenantName
            Metadata      = $metadata
            AssessedAt    = [datetime]::UtcNow
            AssessedBy    = $context.Account
            ModuleVersion = (Get-Module M365GapAssessment).Version.ToString()
            Domains       = $Domain
            Licensing     = $licensing
            Sessions      = $sessions
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

        $branding = @{ PreparedBy = $PreparedBy; BrandColor = $BrandColor; LogoPath = $LogoPath; HideTenantId = [bool]$HideTenantId; CisView = [bool]$CisView }
        # --- Export --------------------------------------------------------------------------
        if (-not $NoExport) {
            Write-Progress -Id 1 -Activity "M365 Gap Assessment [$($context.TenantId)]" -Status 'Exporting reports' -PercentComplete ($base + 95 / $tenants.Count)
            $folderName = Get-AssessmentBaseName -Assessment $assessment
            $folder = Join-Path $ExportPath $folderName
            if (Test-Path -LiteralPath $folder) { $folder = Join-Path $ExportPath ('{0}-{1}' -f $folderName, (Get-Date -Format 'HHmm')) }
            $assessment.ExportedFiles = @(Export-M365GapReport -Assessment $assessment -ExportPath $folder -Format $Format -Branding $branding -IncludeEvidence:$IncludeEvidence)
        }
        $assessment
    }
    Write-Progress -Id 1 -Activity 'M365 Gap Assessment' -Completed
}
