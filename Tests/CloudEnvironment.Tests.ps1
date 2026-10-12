#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Sovereign cloud handling: one table drives Graph, Exchange, Security & Compliance and Teams; the session must land in the cloud
# that was requested; clouds never run against a live tenant say so. Every connect call is a recording fake: nothing here can
# reach a real tenant or open a sign-in prompt.

BeforeDiscovery {
    $script:Clouds = @(
        @{ Env = 'Global';   Exchange = 'O365Default';      TeamsSupported = $true;  TeamsName = $null;        Tested = $true }
        @{ Env = 'USGov';    Exchange = 'O365USGovGCCHigh'; TeamsSupported = $true;  TeamsName = 'TeamsGCCH';  Tested = $false }
        @{ Env = 'USGovDoD'; Exchange = 'O365USGovDoD';     TeamsSupported = $true;  TeamsName = 'TeamsDOD';   Tested = $false }
        @{ Env = 'China';    Exchange = 'O365China';        TeamsSupported = $false; TeamsName = $null;        Tested = $false }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop

    InModuleScope M365GapAssessment {
        $script:Calls = @()
        $script:Ctx = $null
        $script:CtxEnvOverride = $null
        # Connect-M365Assessment reads the signed-in user's roles even with -SkipRoleCheck (for the Global Administrator guard).
        function script:Get-GraphPagedResult { param([Parameter(ValueFromRemainingArguments = $true)]$R) [pscustomobject]@{ displayName = 'Global Reader' } }
        function script:Get-MgContext { $script:Ctx }
        function script:Disconnect-MgGraph { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += 'MG-DISCONNECT'; $script:Ctx = $null }
        function script:Connect-MgGraph {
            param($Environment, [Parameter(ValueFromRemainingArguments = $true)]$R)
            $script:Calls += "MG-CONNECT Environment=$Environment"
            $env = if ($script:CtxEnvOverride) { $script:CtxEnvOverride } else { $Environment }
            $script:Ctx = [pscustomobject]@{ Environment = $env; TenantId = 'tenant-1'; Account = 'admin@contoso.com'; AuthType = 'Delegated'; Scopes = $script:RequiredScopes; ClientId = 'c' }
        }
        function script:Get-Module { param([Parameter(ValueFromRemainingArguments = $true)]$R) [pscustomobject]@{ Name = 'Stub'; Version = [version]'1.0.0' } }
        function script:Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
        function script:Connect-ExchangeOnline { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += "EXO $($R -join ' ')" }
        function script:Connect-IPPSSession { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += "IPPS $($R -join ' ')" }
        function script:Disconnect-ExchangeOnline { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += 'EXO-DISCONNECT' }
        function script:Connect-MicrosoftTeams { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += "TEAMS $($R -join ' ')" }
        function script:Disconnect-MicrosoftTeams { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += 'TEAMS-DISCONNECT' }
    }
    function script:Reset-Cloud {
        InModuleScope M365GapAssessment {
            $script:Calls = @(); $script:Ctx = $null; $script:CtxEnvOverride = $null
            $script:CloudEnvironmentName = 'Global'; $script:ExchangeSessionOpen = $false; $script:ComplianceSessionOpen = $false
        }
    }
    function script:Get-Calls { InModuleScope M365GapAssessment { @($script:Calls) } }
    function script:Get-CloudName { InModuleScope M365GapAssessment { $script:CloudEnvironmentName } }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Cloud table' {
    It '<Env>: Exchange <Exchange>, Teams supported <TeamsSupported> (<TeamsName>), live-tested <Tested>' -ForEach $script:Clouds {
        $c = InModuleScope M365GapAssessment -Parameters @{ E = $Env } { Get-CloudEnvironment -Name $E }
        $c.Exchange | Should -Be $Exchange
        $c.TeamsSupported | Should -Be $TeamsSupported
        $c.TeamsName | Should -Be $TeamsName
        $c.LiveTested | Should -Be $Tested
    }
    It 'only the commercial cloud is marked as live-tested' {
        $tested = InModuleScope M365GapAssessment { @($script:CloudEnvironments.Values | Where-Object LiveTested | ForEach-Object Name) }
        $tested -join ',' | Should -Be 'Global'
    }
    It 'rejects the retired Germany cloud with an explanation' {
        { InModuleScope M365GapAssessment { Get-CloudEnvironment -Name 'Germany' } } | Should -Throw '*retired*'
    }
    It 'rejects an unknown cloud and lists the valid ones' {
        { InModuleScope M365GapAssessment { Get-CloudEnvironment -Name 'Mars' } } | Should -Throw '*Valid values: Global, USGov, USGovDoD, China*'
    }
}

Describe 'Connect-M365Assessment -Environment' {
    BeforeEach { Reset-Cloud }

    It '<Env>: connects Graph in that cloud and records it for the other services' -ForEach $script:Clouds {
        $null = Connect-M365Assessment -Environment $Env -SkipRoleCheck -WarningAction SilentlyContinue
        Get-Calls | Should -Contain "MG-CONNECT Environment=$Env"
        Get-CloudName | Should -Be $Env
    }
    It 'warns that a cloud without a live test is untested' {
        $null = Connect-M365Assessment -Environment USGov -SkipRoleCheck -WarningVariable w -WarningAction SilentlyContinue
        ($w -join ' ') | Should -BeLike '*USGov*not been tested*'
    }
    It 'does not warn for the commercial cloud' {
        $null = Connect-M365Assessment -Environment Global -SkipRoleCheck -WarningVariable w -WarningAction SilentlyContinue
        $w | Should -BeNullOrEmpty
    }
    It 'refuses and disconnects when the session lands in a different cloud than requested' {
        InModuleScope M365GapAssessment { $script:CtxEnvOverride = 'Global' }
        { Connect-M365Assessment -Environment USGov -SkipRoleCheck -WarningAction SilentlyContinue } | Should -Throw "*'Global' cloud*'USGov' was requested*"
        Get-Calls | Should -Contain 'MG-DISCONNECT'
        Get-CloudName | Should -Be 'Global'   # nothing downstream is pointed at the wrong cloud
    }
    It 'reconnects when an existing session is in another cloud' {
        $null = Connect-M365Assessment -Environment Global -SkipRoleCheck
        InModuleScope M365GapAssessment { $script:Calls = @() }
        $null = Connect-M365Assessment -Environment USGov -SkipRoleCheck -WarningAction SilentlyContinue
        $calls = Get-Calls
        $calls | Should -Contain 'MG-DISCONNECT'
        $calls | Should -Contain 'MG-CONNECT Environment=USGov'
    }
    It 'reuses an existing session in the same cloud' {
        $null = Connect-M365Assessment -Environment Global -SkipRoleCheck
        InModuleScope M365GapAssessment { $script:Calls = @() }
        $null = Connect-M365Assessment -Environment Global -SkipRoleCheck
        Get-Calls | Should -BeNullOrEmpty
    }
    It 'rejects values outside the known clouds at parameter binding' {
        { Connect-M365Assessment -Environment Germany -SkipRoleCheck } | Should -Throw '*Germany*'
    }
}

Describe 'Exchange and Security & Compliance follow the cloud' {
    BeforeEach { Reset-Cloud }

    It '<Env>: Exchange session' -ForEach $script:Clouds {
        InModuleScope M365GapAssessment -Parameters @{ E = $Env } { $script:CloudEnvironmentName = $E; $null = Start-ExchangeSession }
        $call = Get-Calls | Where-Object { $_ -like 'EXO *' }
        if ($Exchange -eq 'O365Default') { $call | Should -Not -BeLike '*ExchangeEnvironmentName*' }
        else { $call | Should -BeLike "*-ExchangeEnvironmentName: $Exchange*" }
    }
    It '<Env>: Security & Compliance session' -ForEach $script:Clouds {
        InModuleScope M365GapAssessment -Parameters @{ E = $Env } { $script:CloudEnvironmentName = $E; $null = Start-ComplianceSession }
        $call = Get-Calls | Where-Object { $_ -like 'IPPS *' }
        if ($Exchange -eq 'O365Default') { $call | Should -Not -BeLike '*ExchangeEnvironmentName*' }
        else { $call | Should -BeLike "*-ExchangeEnvironmentName: $Exchange*" }
    }
}

Describe 'Teams follows the cloud' {
    BeforeEach { Reset-Cloud }

    It 'Global: no Teams environment name is passed' {
        $null = InModuleScope M365GapAssessment { Get-TeamsGaps }
        (Get-Calls | Where-Object { $_ -like 'TEAMS *' }) | Should -Not -BeLike '*TeamsEnvironmentName*'
    }
    It 'USGov: connects with TeamsGCCH' {
        $null = InModuleScope M365GapAssessment { $script:CloudEnvironmentName = 'USGov'; Get-TeamsGaps }
        (Get-Calls | Where-Object { $_ -like 'TEAMS *' }) | Should -BeLike '*-TeamsEnvironmentName: TeamsGCCH*'
    }
    It 'USGovDoD: connects with TeamsDOD' {
        $null = InModuleScope M365GapAssessment { $script:CloudEnvironmentName = 'USGovDoD'; Get-TeamsGaps }
        (Get-Calls | Where-Object { $_ -like 'TEAMS *' }) | Should -BeLike '*-TeamsEnvironmentName: TeamsDOD*'
    }
    It 'China: reports all 11 Teams checks NotAssessed with the reason and never connects' {
        $r = InModuleScope M365GapAssessment { $script:CloudEnvironmentName = 'China'; Get-TeamsGaps 3>$null }
        @($r).Count | Should -Be 11
        ($r | Where-Object Status -ne 'NotAssessed') | Should -BeNullOrEmpty
        $r[0].Detail | Should -BeLike '*not available for the Microsoft 365 operated by 21Vianet*'
        Get-Calls | Where-Object { $_ -like 'TEAMS *' } | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-M365SecurityReview -Environment' {
    It 'accepts exactly the supported clouds' {
        $values = (Get-Command Invoke-M365SecurityReview).Parameters['Environment'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues }
        $values -join ',' | Should -Be 'Global,USGov,USGovDoD,China'
    }
    It 'rejects Germany before doing any work' {
        { Invoke-M365SecurityReview -TenantId contoso.com -Environment Germany -NoExport -NoPrompt } | Should -Throw '*Germany*'
    }
    It 'passes the chosen cloud to Connect-M365Assessment' {
        Reset-Cloud
        InModuleScope M365GapAssessment {
            $script:Seen = $null
            function script:Connect-M365Assessment { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Seen = $R -join ' '; [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'a@b' } }
            function script:Get-LicenseInventory { $null }
            function script:Get-LicenseGaps { param($Inventory) @() }
            function script:Invoke-GraphRequestWithRetry { param($Uri) [pscustomobject]@{ value = @([pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @() }) } }
            $null = Invoke-M365SecurityReview -TenantId contoso.com -Environment USGov -Domain Licensing -NoExport -NoPrompt 3>$null
        }
        (InModuleScope M365GapAssessment { $script:Seen }) | Should -BeLike '*-Environment: USGov*'
    }
}

Describe 'Documentation' {
    It 'the README names every supported cloud and says which are untested' {
        $readme = Get-Content -Raw (Join-Path $PSScriptRoot '../M365GapAssessment/README.md')
        foreach ($c in 'USGov', 'USGovDoD', 'China') { $readme | Should -BeLike "*$c*" }
        $readme | Should -BeLike '*not*tested*'
    }
}
