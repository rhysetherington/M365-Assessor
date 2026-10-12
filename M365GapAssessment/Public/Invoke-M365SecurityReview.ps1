function Invoke-M365SecurityReview {
    <#
    .SYNOPSIS
        Runs a read-only Microsoft 365 security gap assessment for one or more tenants and writes the reports.
    .DESCRIPTION
        Signs in (interactive by default), runs the selected check domains, scores the result, and writes JSON, Markdown and/or HTML
        reports. Nothing is ever changed in the tenant: Microsoft Graph calls are GET requests and the Exchange, Purview and Teams
        domains use Get-* cmdlets only. Global Reader is enough; a Global Administrator is asked to confirm first.
        The default domains need only the Graph sign-in. ExchangeOnline, DefenderO365, Purview and Teams are opt-in because each needs
        its own PowerShell module and one more sign-in. If -TenantId is omitted you are asked for it; nothing about a tenant is stored.
        After sign-in you are also asked a few report details (client name, assessor and so on); -NoPrompt accepts the defaults.
    .PARAMETER TenantId
        One or more tenants, each a GUID or a domain name (contoso.onmicrosoft.com). Asked for when omitted.
    .PARAMETER ExportPath
        Folder the reports are written under; each run gets its own subfolder named ClientName-YYYY-MM-DD. Defaults to .\M365Assessment.
    .PARAMETER Format
        JSON, Markdown and/or HTML. The JSON findings file is always written. Default: JSON and Markdown.
    .PARAMETER Credential
        App-only sign-in with a client secret: the user name is the application (client) ID and the password is the secret.
    .PARAMETER ClientId
        Application (client) ID for app-only sign-in with a certificate; use together with -CertificateThumbprint.
    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate for app-only sign-in; use together with -ClientId.
    .PARAMETER UseDeviceAuthentication
        Sign in with a device code instead of a browser window (for headless machines). Blocked where Security Defaults is on.
    .PARAMETER Environment
        Microsoft cloud: Global (default), USGov (GCC High), USGovDoD or China. Only Global has been tested against a live tenant.
    .PARAMETER Domain
        Which check domains to run. Default: Licensing, EntraID, EntraPolicy, Defender, SecureScore, EmailDns, SharePoint.
        Opt-in: ExchangeOnline, DefenderO365, Purview, Teams.
    .PARAMETER DohEndpoint
        DNS-over-HTTPS resolver used for the SPF, DMARC and DKIM lookups on macOS and Linux. Your verified domain names are sent to it.
    .PARAMETER StaleDays
        Days without sign-in after which an account or role assignment counts as stale. Default 90.
    .PARAMETER SecretWarningDays
        Warn about application secrets and certificates that expire within this many days. Default 30.
    .PARAMETER TargetScorePercent
        Microsoft Secure Score percentage the tenant is expected to reach. Default 70.
    .PARAMETER AcceptedRiskPath
        JSON file of risks the organisation has knowingly accepted for this tenant. Matching gaps are reported as Accepted.
    .PARAMETER ClientName
        Client name shown in the report and used to name the output folder. Default: the first label of the tenant's primary domain.
    .PARAMETER AssessmentName
        Title of the assessment. Default: Microsoft 365 Security Gap Assessment.
    .PARAMETER AssessorName
        Who performed the assessment. Default: the signed-in account.
    .PARAMETER AssessmentDate
        Assessment date as yyyy-MM-dd. Default: today.
    .PARAMETER Reference
        Optional engagement or ticket reference shown in the report header.
    .PARAMETER NoPrompt
        Do not ask for the assessment details; use the parameters and defaults.
    .PARAMETER PreparedBy
        Name shown as the author of the report.
    .PARAMETER BrandColor
        Accent colour of the HTML report as #RRGGBB.
    .PARAMETER LogoPath
        PNG, JPEG or SVG file embedded in the HTML report.
    .PARAMETER HideTenantId
        Leave the tenant ID out of the HTML and Markdown reports (it remains in the JSON file).
    .PARAMETER IncludeEvidence
        Also write evidence\<FindingId>.csv with the full list of affected items for each gap.
    .PARAMETER CisView
        Add a section that regroups findings by CIS Microsoft 365 Foundations recommendation.
    .PARAMETER SkipRoleCheck
        Do not require the signed-in account to hold a read role. It does not skip the Global Administrator confirmation.
    .PARAMETER AllowGlobalAdministrator
        Run as Global Administrator without being asked. Needed for unattended runs that sign in with that role; a warning is still printed.
    .PARAMETER NoExport
        Return the results without writing any files.
    .EXAMPLE
        Invoke-M365SecurityReview -TenantId contoso.onmicrosoft.com -Format JSON,Markdown,HTML
    .EXAMPLE
        'tenantA.onmicrosoft.com','tenantB.onmicrosoft.com' | ForEach-Object { Invoke-M365SecurityReview -TenantId $_ -UseDeviceAuthentication }
    .EXAMPLE
        Invoke-M365SecurityReview -TenantId contoso.onmicrosoft.com -Domain EntraID,EntraPolicy,ExchangeOnline,Teams -NoPrompt
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
        [switch]$AllowGlobalAdministrator,
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
        $connect = @{ SkipRoleCheck = $SkipRoleCheck; Environment = $Environment; AllowGlobalAdministrator = [bool]$AllowGlobalAdministrator }
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
