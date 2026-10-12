#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Global Administrator guard: Global Reader is enough for every check, so using a Global Administrator account is confirmed by a person
# (default No) or, in a session that cannot ask, stopped unless -AllowGlobalAdministrator was passed on purpose. Every sign-in call and
# the keyboard are fakes: nothing here reaches a tenant or waits for input.

BeforeDiscovery {
    $script:Declines = @(
        @{ Name = 'n';                Answer = 'n' }
        @{ Name = 'no';               Answer = 'no' }
        @{ Name = 'an empty line (Enter): the default is No'; Answer = '' }
        @{ Name = 'whitespace only';  Answer = '   ' }
        @{ Name = 'an unrelated word'; Answer = 'maybe' }
        @{ Name = 'yess (not an exact yes)'; Answer = 'yess' }
        @{ Name = 'y with extra text'; Answer = 'y please' }
    )
    $script:Accepts = @(
        @{ Name = 'y';   Answer = 'y' }
        @{ Name = 'Y';   Answer = 'Y' }
        @{ Name = 'yes'; Answer = 'yes' }
        @{ Name = 'YES'; Answer = 'YES' }
        @{ Name = 'y with surrounding spaces'; Answer = '  y  ' }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop

    InModuleScope M365GapAssessment {
        $script:Calls = @(); $script:Ctx = $null; $script:Roles = @('Global Reader'); $script:Interactive = $true
        $script:Answer = 'n'; $script:ReadThrows = $false; $script:AppOnly = $false; $script:CtxAccount = 'admin@contoso.com'
        function script:Get-MgContext { $script:Ctx }
        function script:Disconnect-MgGraph { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += 'MG-DISCONNECT'; $script:Ctx = $null }
        function script:Connect-MgGraph {
            param($Environment, [Parameter(ValueFromRemainingArguments = $true)]$R)
            $script:Calls += 'MG-CONNECT'
            $script:Ctx = [pscustomobject]@{
                Environment = $Environment; TenantId = 'tenant-1'; Account = $(if ($script:AppOnly) { $null } else { $script:CtxAccount })
                AuthType = $(if ($script:AppOnly) { 'AppOnly' } else { 'Delegated' }); Scopes = $script:RequiredScopes; ClientId = 'client-1'
            }
        }
        function script:Get-GraphPagedResult { param([Parameter(ValueFromRemainingArguments = $true)]$R) @($script:Roles | ForEach-Object { [pscustomobject]@{ displayName = $_ } }) }
        function script:Test-InteractiveSession { $script:Interactive }
        function script:Read-GlobalAdminConfirmation {
            param($Prompt)
            $script:Calls += 'PROMPT'
            if ($script:ReadThrows) { throw 'PowerShell is in NonInteractive mode. Read and Prompt functionality is not available.' }
            $script:Answer
        }
    }

    function script:Reset-Guard {
        InModuleScope M365GapAssessment {
            $script:Calls = @(); $script:Ctx = $null; $script:Roles = @('Global Reader'); $script:Interactive = $true
            $script:Answer = 'n'; $script:ReadThrows = $false; $script:AppOnly = $false; $script:CtxAccount = 'admin@contoso.com'
            $script:GlobalAdminAcknowledged = $null; $script:AssessmentContext = $null; $script:CloudEnvironmentName = 'Global'
            # Restore the default role lookup: a test that replaced it with a failing one must not leak into the next test.
            function script:Get-GraphPagedResult { param([Parameter(ValueFromRemainingArguments = $true)]$R) @($script:Roles | ForEach-Object { [pscustomobject]@{ displayName = $_ } }) }
        }
    }
    function script:Set-World($Roles, [bool]$Interactive = $true, $Answer = 'n', [bool]$ReadThrows = $false, [bool]$AppOnly = $false) {
        InModuleScope M365GapAssessment -Parameters @{ R = $Roles; I = $Interactive; A = $Answer; T = $ReadThrows; P = $AppOnly } {
            $script:Roles = $R; $script:Interactive = $I; $script:Answer = $A; $script:ReadThrows = $T; $script:AppOnly = $P
        }
    }
    function script:Get-Calls { InModuleScope M365GapAssessment { @($script:Calls) } }
    function script:Get-Acknowledged { InModuleScope M365GapAssessment { $script:GlobalAdminAcknowledged } }

    # Runs Connect-M365Assessment and returns what happened: the result, the terminating error message, and warnings.
    function script:Connect([hashtable]$Extra = @{}) {
        $out = [ordered]@{ Result = $null; Error = $null; Warnings = @() }
        try { $out.Result = Connect-M365Assessment @Extra -WarningVariable w -WarningAction SilentlyContinue }
        catch { $out.Error = $_.Exception.Message }
        $out.Warnings = @($w)
        [pscustomobject]$out
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Accounts that are not Global Administrator' {
    BeforeEach { Reset-Guard }

    It '<Role> is not asked to confirm' -ForEach @(@{ Role = 'Global Reader' }, @{ Role = 'Security Reader' }, @{ Role = 'Security Administrator' }) {
        Set-World @($Role)
        $r = Connect
        $r.Error | Should -BeNullOrEmpty
        Get-Calls | Should -Not -Contain 'PROMPT'
        $r.Warnings | Should -BeNullOrEmpty
    }
    It 'a Global Reader in a non-interactive session simply runs' {
        Set-World @('Global Reader') -Interactive $false
        (Connect).Error | Should -BeNullOrEmpty
    }
}

Describe 'Global Administrator in an interactive session' {
    BeforeEach { Reset-Guard }

    It 'warns, then asks once, and continues on <Name>' -ForEach $script:Accepts {
        Set-World @('Global Administrator') -Answer $Answer
        $r = Connect
        $r.Error | Should -BeNullOrEmpty
        $r.Result.Account | Should -Be 'admin@contoso.com'
        @(Get-Calls | Where-Object { $_ -eq 'PROMPT' }).Count | Should -Be 1
        ($r.Warnings -join ' ') | Should -BeLike '*holds the Global Administrator role*Global Reader is enough*'
    }
    It 'stops, disconnects and records no session on <Name>' -ForEach $script:Declines {
        Set-World @('Global Administrator') -Answer $Answer
        $r = Connect
        $r.Error | Should -BeLike "*Cancelled*'admin@contoso.com'*Global Administrator*"
        $r.Result | Should -BeNullOrEmpty
        Get-Calls | Should -Contain 'MG-DISCONNECT'
        InModuleScope M365GapAssessment { $script:AssessmentContext } | Should -BeNullOrEmpty
    }
    It 'treats an account that holds both Global Administrator and Global Reader as a Global Administrator' {
        Set-World @('Global Reader', 'Global Administrator') -Answer 'n'
        (Connect).Error | Should -BeLike '*Cancelled*'
        Get-Calls | Should -Contain 'PROMPT'
    }
    It 'stops (does not hang) when reading the answer fails, as in a -NonInteractive host' {
        Set-World @('Global Administrator') -ReadThrows $true
        $r = Connect
        $r.Error | Should -BeLike '*cannot ask for confirmation*'
        Get-Calls | Should -Contain 'MG-DISCONNECT'
    }
}

Describe 'Global Administrator in a session that cannot ask (automation)' {
    BeforeEach { Reset-Guard }

    It 'halts with a message that names the fix, without ever prompting' {
        Set-World @('Global Administrator') -Interactive $false -Answer 'y'
        $r = Connect
        $r.Error | Should -BeLike "*'admin@contoso.com'*Global Administrator*cannot ask for confirmation*Nothing was assessed*"
        $r.Error | Should -BeLike '*-AllowGlobalAdministrator*'
        $r.Error | Should -BeLike '*Global Reader*'
        Get-Calls | Should -Not -Contain 'PROMPT'
        Get-Calls | Should -Contain 'MG-DISCONNECT'
        $r.Result | Should -BeNullOrEmpty
    }
    It 'does not let a pre-set answer slip past: it never asks, so it cannot be answered' {
        Set-World @('Global Administrator') -Interactive $false -Answer 'yes'
        (Connect).Error | Should -Not -BeNullOrEmpty
    }
}

Describe '-AllowGlobalAdministrator' {
    BeforeEach { Reset-Guard }

    It 'runs without asking, even in a non-interactive session, and says so in a warning' {
        Set-World @('Global Administrator') -Interactive $false
        $r = Connect @{ AllowGlobalAdministrator = $true }
        $r.Error | Should -BeNullOrEmpty
        Get-Calls | Should -Not -Contain 'PROMPT'
        ($r.Warnings -join ' ') | Should -BeLike '*allowed by -AllowGlobalAdministrator*Global Reader is enough*'
    }
    It 'changes nothing for an account that is not a Global Administrator' {
        Set-World @('Global Reader')
        $r = Connect @{ AllowGlobalAdministrator = $true }
        $r.Error | Should -BeNullOrEmpty
        $r.Warnings | Should -BeNullOrEmpty
    }
}

Describe '-SkipRoleCheck does not skip the guard' {
    BeforeEach { Reset-Guard }

    It 'still asks a Global Administrator to confirm' {
        Set-World @('Global Administrator') -Answer 'n'
        (Connect @{ SkipRoleCheck = $true }).Error | Should -BeLike '*Cancelled*'
        Get-Calls | Should -Contain 'PROMPT'
    }
    It 'still halts a Global Administrator in a non-interactive session' {
        Set-World @('Global Administrator') -Interactive $false
        (Connect @{ SkipRoleCheck = $true }).Error | Should -BeLike '*-AllowGlobalAdministrator*'
    }
    It 'still waives the requirement to hold a read role (an account with no roles can run)' {
        Set-World @()
        (Connect @{ SkipRoleCheck = $true }).Error | Should -BeNullOrEmpty
    }
    It 'warns, instead of failing, when the roles cannot be read at all' {
        InModuleScope M365GapAssessment { function script:Get-GraphPagedResult { param([Parameter(ValueFromRemainingArguments = $true)]$R) throw 'Forbidden' } }
        $r = Connect @{ SkipRoleCheck = $true }
        $r.Error | Should -BeNullOrEmpty
        ($r.Warnings -join ' ') | Should -BeLike '*not possible to check whether this account is a Global Administrator*'
    }
    It 'without -SkipRoleCheck an unreadable role list is an error' {
        InModuleScope M365GapAssessment { function script:Get-GraphPagedResult { param([Parameter(ValueFromRemainingArguments = $true)]$R) throw 'Forbidden' } }
        (Connect).Error | Should -BeLike '*Could not read the signed-in user*directory roles*'
    }
}

Describe 'Confirmation is remembered for the same sign-in only' {
    BeforeEach { Reset-Guard }

    It 'does not ask again when the same session is reused for the same tenant and account' {
        Set-World @('Global Administrator') -Answer 'y'
        $null = Connect
        $null = Connect
        @(Get-Calls | Where-Object { $_ -eq 'PROMPT' }).Count | Should -Be 1
    }
    It 'asks again after a fresh sign-in' {
        Set-World @('Global Administrator') -Answer 'y'
        $null = Connect
        $null = Connect @{ Force = $true }
        @(Get-Calls | Where-Object { $_ -eq 'PROMPT' }).Count | Should -Be 2
    }
    It 'asks again for a different account' {
        Set-World @('Global Administrator') -Answer 'y'
        $null = Connect
        InModuleScope M365GapAssessment { $script:CtxAccount = 'other.admin@contoso.com'; $script:Ctx.Account = 'other.admin@contoso.com' }
        $null = Connect
        @(Get-Calls | Where-Object { $_ -eq 'PROMPT' }).Count | Should -Be 2
    }
    It 'a refusal is not remembered: the next attempt asks again' {
        Set-World @('Global Administrator') -Answer 'n'
        $null = Connect
        $null = Connect
        @(Get-Calls | Where-Object { $_ -eq 'PROMPT' }).Count | Should -Be 2
        Get-Acknowledged | Should -BeNullOrEmpty
    }
}

Describe 'App-only sessions' {
    BeforeEach { Reset-Guard }
    It 'are not role-checked and never prompt (an app registration has no directory role to confirm)' {
        Set-World @('Global Administrator') -AppOnly $true
        $r = Connect @{ ClientId = 'client-1'; CertificateThumbprint = 'ABC123' }
        $r.Error | Should -BeNullOrEmpty
        Get-Calls | Should -Not -Contain 'PROMPT'
    }
}

Describe 'Invoke-M365SecurityReview' {
    It 'exposes -AllowGlobalAdministrator as a switch' {
        (Get-Command Invoke-M365SecurityReview).Parameters['AllowGlobalAdministrator'].ParameterType.Name | Should -Be 'SwitchParameter'
    }
    It 'passes the switch (off by default) to Connect-M365Assessment' {
        InModuleScope M365GapAssessment {
            $script:Seen = @()
            function script:Connect-M365Assessment { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Seen += ($R -join ' '); [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'a@b' } }
            function script:Get-LicenseInventory { $null }
            function script:Get-LicenseGaps { param($Inventory) @() }
            function script:Invoke-GraphRequestWithRetry { param($Uri) [pscustomobject]@{ value = @([pscustomobject]@{ displayName = 'Contoso'; verifiedDomains = @() }) } }
            $null = Invoke-M365SecurityReview -TenantId contoso.com -Domain Licensing -NoExport -NoPrompt 3>$null
            $null = Invoke-M365SecurityReview -TenantId contoso.com -Domain Licensing -NoExport -NoPrompt -AllowGlobalAdministrator 3>$null
        }
        $seen = InModuleScope M365GapAssessment { $script:Seen }
        $seen[0] | Should -BeLike '*-AllowGlobalAdministrator: False*'
        $seen[1] | Should -BeLike '*-AllowGlobalAdministrator: True*'
    }
    It 'stops before any collector runs when the guard halts the connection' {
        InModuleScope M365GapAssessment {
            $script:CollectorRan = $false
            function script:Connect-M365Assessment { param([Parameter(ValueFromRemainingArguments = $true)]$R) throw 'Signed in as Global Administrator ... Nothing was assessed.' }
            function script:Get-LicenseInventory { $script:CollectorRan = $true; $null }
            function script:Get-LicenseGaps { param($Inventory) $script:CollectorRan = $true; @() }
        }
        { InModuleScope M365GapAssessment { Invoke-M365SecurityReview -TenantId contoso.com -Domain Licensing -NoExport -NoPrompt } } | Should -Throw '*Nothing was assessed*'
        InModuleScope M365GapAssessment { $script:CollectorRan } | Should -BeFalse
    }
}

Describe 'Documentation' {
    It 'the README explains the Global Administrator confirmation and -AllowGlobalAdministrator' {
        $readme = Get-Content -Raw (Join-Path (Split-Path (Get-ModuleUnderTestPath)) 'README.md')
        $readme | Should -BeLike '*-AllowGlobalAdministrator*'
        $readme | Should -BeLike '*Global Administrator*confirm*'
        $readme | Should -BeLike '*-SkipRoleCheck*'
    }
}
