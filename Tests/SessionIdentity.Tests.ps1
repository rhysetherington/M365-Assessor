#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Session identity: which account each service (Graph, Exchange, Security & Compliance, Teams) really signed in as, so a run billed
# as "read-only Global Reader" cannot be silently answered by a different, more privileged cached login. Every connect call is a fake.

BeforeDiscovery {
    $script:TeamsShapes = @(
        @{ Name = 'Account.Id';              Conn = [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'reader@contoso.com' } }; Expected = 'reader@contoso.com' }
        @{ Name = 'Account as a plain string'; Conn = [pscustomobject]@{ Account = 'reader@contoso.com' };                         Expected = 'reader@contoso.com' }
        @{ Name = 'no Account property';      Conn = [pscustomobject]@{ Tenant = 'x' };                                          Expected = $null }
        @{ Name = 'null connection result';   Conn = $null;                                                                      Expected = $null }
        @{ Name = 'Account with an empty Id'; Conn = [pscustomobject]@{ Account = [pscustomobject]@{ Id = '' } };                 Expected = $null }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop

    InModuleScope M365GapAssessment {
        $script:ConnInfo = @()
        $script:ConnInfoThrows = $false
        $script:TeamsResult = $null
        function script:Get-ConnectionInformation { param([Parameter(ValueFromRemainingArguments = $true)]$R) if ($script:ConnInfoThrows) { throw 'no connection' }; $script:ConnInfo }
        function script:Get-Module { param([Parameter(ValueFromRemainingArguments = $true)]$R) [pscustomobject]@{ Name = 'Stub'; Version = [version]'1.0.0' } }
        function script:Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
        function script:Connect-ExchangeOnline { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
        function script:Connect-IPPSSession { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
        function script:Disconnect-ExchangeOnline { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
        function script:Connect-MicrosoftTeams { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:TeamsResult }
        function script:Disconnect-MicrosoftTeams { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
    }

    function script:Reset-Identity {
        InModuleScope M365GapAssessment {
            $script:SessionIdentities = [ordered]@{}; $script:ConnInfo = @(); $script:ConnInfoThrows = $false; $script:TeamsResult = $null
            $script:ExchangeSessionOpen = $false; $script:ComplianceSessionOpen = $false; $script:CloudEnvironmentName = 'Global'
        }
    }
    function script:Set-Conn($Sessions) { InModuleScope M365GapAssessment -Parameters @{ S = $Sessions } { $script:ConnInfo = $S } }
    function script:Report { InModuleScope M365GapAssessment { @(Get-SessionIdentityReport) } }
    function script:Reg($Service, $Account) { InModuleScope M365GapAssessment -Parameters @{ S = $Service; A = $Account } { Register-SessionIdentity -Service $S -Account $A } }
    function script:Row($Service) { Report | Where-Object Service -eq $Service }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Get-ExchangeSessionAccount' {
    BeforeEach { Reset-Identity }
    It 'reads the account of a single connected session' {
        Set-Conn @([pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'reader@contoso.com'; ConnectionUri = 'https://outlook.office365.com' })
        InModuleScope M365GapAssessment { Get-ExchangeSessionAccount -Kind Exchange } | Should -Be 'reader@contoso.com'
    }
    It 'picks the Exchange and the compliance session apart by endpoint' {
        Set-Conn @(
            [pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'exo@contoso.com'; ConnectionUri = 'https://outlook.office365.com/powershell-liveid' }
            [pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'ipps@contoso.com'; ConnectionUri = 'https://ps.compliance.protection.outlook.com/powershell-liveid' })
        InModuleScope M365GapAssessment { Get-ExchangeSessionAccount -Kind Exchange } | Should -Be 'exo@contoso.com'
        InModuleScope M365GapAssessment { Get-ExchangeSessionAccount -Kind Compliance } | Should -Be 'ipps@contoso.com'
    }
    It 'ignores sessions that are not connected' {
        Set-Conn @([pscustomobject]@{ State = 'Disconnected'; UserPrincipalName = 'old@contoso.com'; ConnectionUri = 'x' })
        InModuleScope M365GapAssessment { Get-ExchangeSessionAccount -Kind Exchange } | Should -BeNullOrEmpty
    }
    It 'returns nothing when there is no session' {
        InModuleScope M365GapAssessment { Get-ExchangeSessionAccount -Kind Exchange } | Should -BeNullOrEmpty
    }
    It 'returns nothing (not an error) when the cmdlet fails' {
        InModuleScope M365GapAssessment { $script:ConnInfoThrows = $true }
        InModuleScope M365GapAssessment { Get-ExchangeSessionAccount -Kind Exchange } | Should -BeNullOrEmpty
    }
}

Describe 'Get-TeamsSessionAccount' {
    It '<Name>' -ForEach $script:TeamsShapes {
        InModuleScope M365GapAssessment -Parameters @{ C = $Conn } { Get-TeamsSessionAccount -Connection $C } | Should -Be $Expected
    }
}

Describe 'Get-SessionIdentityReport' {
    BeforeEach { Reset-Identity }
    It 'is empty when nothing is registered' { Report | Should -BeNullOrEmpty }
    It 'treats Graph as matching itself' {
        Reg 'Microsoft Graph' 'reader@contoso.com'
        (Row 'Microsoft Graph').MatchesGraph | Should -Be 'Yes'
    }
    It 'matches the same account regardless of letter case' {
        Reg 'Microsoft Graph' 'Reader@Contoso.com'; Reg 'Exchange Online' 'reader@contoso.COM'
        (Row 'Exchange Online').MatchesGraph | Should -Be 'Yes'
    }
    It 'flags a different account' {
        Reg 'Microsoft Graph' 'reader@contoso.com'; Reg 'Microsoft Teams' 'admin@contoso.com'
        $r = Row 'Microsoft Teams'
        $r.MatchesGraph | Should -Be 'No'
        $r.Account | Should -Be 'admin@contoso.com'
    }
    It 'reports an undetermined account as unknown, not as a match' {
        Reg 'Microsoft Graph' 'reader@contoso.com'; Reg 'Microsoft Teams' $null
        $r = Row 'Microsoft Teams'
        $r.MatchesGraph | Should -Be 'Unknown'
        $r.Account | Should -Be 'unknown'
    }
    It 'does not compare against an app-only Graph session (no user to compare)' {
        Reg 'Microsoft Graph' 'app:1234'; Reg 'Exchange Online' 'someone@contoso.com'
        (Row 'Exchange Online').MatchesGraph | Should -Be 'n/a'
    }
    It 'keeps the order the sessions were registered in' {
        Reg 'Microsoft Graph' 'a@b.com'; Reg 'Exchange Online' 'a@b.com'; Reg 'Microsoft Teams' 'a@b.com'
        (Report | ForEach-Object Service) -join ',' | Should -Be 'Microsoft Graph,Exchange Online,Microsoft Teams'
    }
    It 'is cleared by Reset-CollectorCache so a new tenant starts clean' {
        Reg 'Microsoft Graph' 'a@b.com'
        InModuleScope M365GapAssessment { Reset-CollectorCache }
        Report | Should -BeNullOrEmpty
    }
}

Describe 'Sessions register the account they connected as' {
    BeforeEach { Reset-Identity }
    It 'Exchange Online' {
        Set-Conn @([pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'reader@contoso.com'; ConnectionUri = 'https://outlook.office365.com' })
        $null = InModuleScope M365GapAssessment { Start-ExchangeSession }
        (Row 'Exchange Online').Account | Should -Be 'reader@contoso.com'
    }
    It 'Security & Compliance (Purview)' {
        Set-Conn @([pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'reader@contoso.com'; ConnectionUri = 'https://ps.compliance.protection.outlook.com' })
        $null = InModuleScope M365GapAssessment { Start-ComplianceSession }
        (Row 'Security & Compliance (Purview)').Account | Should -Be 'reader@contoso.com'
    }
    It 'Microsoft Teams' {
        InModuleScope M365GapAssessment { $script:TeamsResult = [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'reader@contoso.com' } } }
        $null = InModuleScope M365GapAssessment { Get-TeamsGaps 3>$null }
        (Row 'Microsoft Teams').Account | Should -Be 'reader@contoso.com'
    }
    It 'records unknown when the service does not say who signed in' {
        $null = InModuleScope M365GapAssessment { Get-TeamsGaps 3>$null }
        (Row 'Microsoft Teams').Account | Should -Be 'unknown'
    }
}

Describe 'Invoke-M365SecurityReview reports and warns about sessions' {
    BeforeAll {
        InModuleScope M365GapAssessment {
            function script:Connect-M365Assessment { param([Parameter(ValueFromRemainingArguments = $true)]$R) [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'reader@contoso.com' } }
            function script:Get-LicenseInventory { $null }
            function script:Get-LicenseGaps { param($Inventory) @() }
            function script:Invoke-GraphRequestWithRetry { param($Uri) [pscustomobject]@{ value = @([pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @() }) } }
        }
        function script:Run { InModuleScope M365GapAssessment { Invoke-M365SecurityReview -TenantId contoso.com -Domain ExchangeOnline -NoExport -NoPrompt -WarningVariable w -WarningAction SilentlyContinue; $script:W = @($w) } }
        # Only the session-identity warnings: the fake Exchange session has no real cmdlets, so collectors add their own warnings too.
        function script:Warnings { InModuleScope M365GapAssessment { @($script:W | Where-Object { $_ -like '*signed in as*' -or $_ -like 'Could not determine which account*' }) } }
    }
    BeforeEach { Reset-Identity }

    It 'attaches the session list to the assessment' {
        Set-Conn @([pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'reader@contoso.com'; ConnectionUri = 'https://outlook.office365.com' })
        $r = Run
        ($r.Sessions | ForEach-Object Service) -join ',' | Should -Be 'Microsoft Graph,Exchange Online'
        ($r.Sessions | Where-Object Service -eq 'Exchange Online').MatchesGraph | Should -Be 'Yes'
    }
    It 'does not warn when every service used the Graph account' {
        Set-Conn @([pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'reader@contoso.com'; ConnectionUri = 'https://outlook.office365.com' })
        $null = Run
        Warnings | Should -BeNullOrEmpty
    }
    It 'warns, naming both accounts, when a service used a different account' {
        Set-Conn @([pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'admin@contoso.com'; ConnectionUri = 'https://outlook.office365.com' })
        $r = Run
        (Warnings -join ' ') | Should -BeLike "*Exchange Online signed in as 'admin@contoso.com'*Graph as 'reader@contoso.com'*"
        ($r.Sessions | Where-Object Service -eq 'Exchange Online').MatchesGraph | Should -Be 'No'
    }
    It 'warns when the account could not be determined' {
        $r = Run
        (Warnings -join ' ') | Should -BeLike '*Could not determine which account Exchange Online signed in as*'
        ($r.Sessions | Where-Object Service -eq 'Exchange Online').Account | Should -Be 'unknown'
    }
}

Describe 'Reports show the sessions' {
    BeforeAll {
        $script:Support = Join-Path $PSScriptRoot 'Support/TestSupport.ps1'
        function script:Assess($Sessions) {
            InModuleScope M365GapAssessment -Parameters @{ S = $script:Support; X = $Sessions } { . $S; $a = New-MockAssessment; if ($null -ne $X) { $a | Add-Member -NotePropertyName Sessions -NotePropertyValue $X }; $a }
        }
        $script:Good = @(
            [pscustomobject]@{ Service = 'Microsoft Graph'; Account = 'reader@contoso.com'; MatchesGraph = 'Yes' }
            [pscustomobject]@{ Service = 'Exchange Online'; Account = 'reader@contoso.com'; MatchesGraph = 'Yes' })
        $script:Mixed = @(
            [pscustomobject]@{ Service = 'Microsoft Graph'; Account = 'reader@contoso.com'; MatchesGraph = 'Yes' }
            [pscustomobject]@{ Service = 'Microsoft Teams'; Account = 'admin@contoso.com'; MatchesGraph = 'No' }
            [pscustomobject]@{ Service = 'Security & Compliance (Purview)'; Account = 'unknown'; MatchesGraph = 'Unknown' })
    }
    It 'lists each service and account in the Markdown and HTML, without a warning when all match' {
        $dir = Join-Path $TestDrive 'good'
        $null = Export-M365GapReport -Assessment (Assess $script:Good) -ExportPath $dir -Format Markdown, HTML
        $md = Get-Content -Raw (Join-Path $dir 'M365_Security_Gap_Assessment.md')
        $md | Should -BeLike '*## Assessment Sessions*'
        $md | Should -BeLike '*| Exchange Online | reader@contoso.com | Yes |*'
        $md | Should -Not -BeLike '*not every service was confirmed*'
        $html = Get-Content -Raw (Join-Path $dir 'M365_Security_Gap_Assessment.html')
        $html | Should -BeLike '*Assessment sessions (accounts used)*'
        $html | Should -Not -BeLike '*Not every service was confirmed*'
    }
    It 'adds a visible note when accounts differ or are unknown' {
        $dir = Join-Path $TestDrive 'mixed'
        $null = Export-M365GapReport -Assessment (Assess $script:Mixed) -ExportPath $dir -Format Markdown, HTML
        $md = Get-Content -Raw (Join-Path $dir 'M365_Security_Gap_Assessment.md')
        $md | Should -BeLike '*| Microsoft Teams | admin@contoso.com | No |*'
        $md | Should -BeLike '*| Security & Compliance (Purview) | unknown | Unknown |*'
        $md | Should -BeLike '*not every service was confirmed to use the same account*'
        (Get-Content -Raw (Join-Path $dir 'M365_Security_Gap_Assessment.html')) | Should -BeLike '*class="s-Gap">No*'
    }
    It 'omits the section for older assessments that have no session data' {
        $dir = Join-Path $TestDrive 'old'
        $null = Export-M365GapReport -Assessment (Assess $null) -ExportPath $dir -Format Markdown, HTML
        (Get-Content -Raw (Join-Path $dir 'M365_Security_Gap_Assessment.md')) | Should -Not -BeLike '*Assessment Sessions*'
        (Get-Content -Raw (Join-Path $dir 'M365_Security_Gap_Assessment.html')) | Should -Not -BeLike '*Assessment sessions*'
    }
    It 'survives a round trip through the JSON and Convert-M365Report' {
        $dir = Join-Path $TestDrive 'trip'
        $null = Export-M365GapReport -Assessment (Assess $script:Mixed) -ExportPath $dir -Format JSON
        $json = Get-Content -Raw (Join-Path $dir 'AssessmentFindings.json') | ConvertFrom-Json
        @($json.Sessions).Count | Should -Be 3
        $out = @(Convert-M365Report -Path (Join-Path $dir 'AssessmentFindings.json') -Format Markdown)
        Get-Content -Raw $out[0] | Should -BeLike '*| Microsoft Teams | admin@contoso.com | No |*'
    }
}

Describe 'Documentation' {
    It 'the README explains the Assessment sessions table and its Yes / No / Unknown / n/a values' {
        $readme = Get-Content -Raw (Join-Path $PSScriptRoot '../M365GapAssessment/README.md')
        $readme | Should -BeLike '*Assessment sessions*'
        # Plain substring checks: the backtick is the escape character in -BeLike wildcard patterns.
        foreach ($v in '`Yes`', '`No`', '`Unknown`', '`n/a`') { $readme.Contains($v) | Should -BeTrue -Because "the README should explain the $v value" }
    }
}
