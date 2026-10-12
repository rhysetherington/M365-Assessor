#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Shared Exchange / compliance session handling (Private/ExchangeSession.ps1). Every connect call is replaced by a recording fake
# inside the module, so no test can reach a real tenant or open a sign-in prompt.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop

    InModuleScope M365GapAssessment {
        $script:Calls = @()
        $script:ConnectFails = $false
        $script:ModuleInstalled = $true
        function script:Get-Module { param([Parameter(ValueFromRemainingArguments = $true)]$R) if ($script:ModuleInstalled) { [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } } }
        function script:Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$R) }
        function script:Connect-ExchangeOnline { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += "EXO $($R -join ' ')"; if ($script:ConnectFails) { throw "boom`nsecond line" } }
        function script:Connect-IPPSSession { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += "IPPS $($R -join ' ')"; if ($script:ConnectFails) { throw 'boom' } }
        function script:Disconnect-ExchangeOnline { param([Parameter(ValueFromRemainingArguments = $true)]$R) $script:Calls += 'DISCONNECT' }
    }

    function script:Reset-Session {
        InModuleScope M365GapAssessment {
            $script:Calls = @(); $script:ConnectFails = $false; $script:ModuleInstalled = $true
            $script:ExchangeSessionOpen = $false; $script:ComplianceSessionOpen = $false
        }
    }
    function script:Get-Calls { InModuleScope M365GapAssessment { @($script:Calls) } }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Start-ExchangeSession' {
    BeforeEach { Reset-Session }

    It 'connects and reports Ready' {
        $r = InModuleScope M365GapAssessment { Start-ExchangeSession }
        $r.Ready | Should -BeTrue
        $r.Error | Should -BeNullOrEmpty
        @(Get-Calls | Where-Object { $_ -like 'EXO*' }).Count | Should -Be 1
    }
    It 'passes the tenant as the organization' {
        $null = InModuleScope M365GapAssessment { Start-ExchangeSession -TenantId 'contoso.com' }
        (Get-Calls | Where-Object { $_ -like 'EXO*' }) | Should -BeLike '*-Organization: contoso.com*'
    }
    It 'reuses the open session instead of signing in again' {
        $null = InModuleScope M365GapAssessment { Start-ExchangeSession; Start-ExchangeSession; Start-ExchangeSession }
        @(Get-Calls | Where-Object { $_ -like 'EXO*' }).Count | Should -Be 1
    }
    It 'reports a failed connection with the first line of the error and does not mark the session open' {
        InModuleScope M365GapAssessment { $script:ConnectFails = $true }
        $r = InModuleScope M365GapAssessment { Start-ExchangeSession }
        $r.Ready | Should -BeFalse
        $r.Error | Should -BeLike '*boom'
        $r.Error | Should -Not -BeLike '*second line*'
        # The next attempt retries rather than assuming it is connected.
        InModuleScope M365GapAssessment { $script:ConnectFails = $false }
        (InModuleScope M365GapAssessment { Start-ExchangeSession }).Ready | Should -BeTrue
    }
    It 'reports a missing module without attempting a connection' {
        InModuleScope M365GapAssessment { $script:ModuleInstalled = $false }
        $r = InModuleScope M365GapAssessment { Start-ExchangeSession }
        $r.Ready | Should -BeFalse
        $r.Error | Should -BeLike '*not installed*'
        Get-Calls | Should -BeNullOrEmpty
    }
}

Describe 'Start-ComplianceSession' {
    BeforeEach { Reset-Session }

    It 'connects with Connect-IPPSSession and is independent of the Exchange session' {
        $null = InModuleScope M365GapAssessment { Start-ExchangeSession; Start-ComplianceSession }
        @(Get-Calls | Where-Object { $_ -like 'EXO*' }).Count | Should -Be 1
        @(Get-Calls | Where-Object { $_ -like 'IPPS*' }).Count | Should -Be 1
    }
    It 'reuses the open compliance session' {
        $null = InModuleScope M365GapAssessment { Start-ComplianceSession; Start-ComplianceSession }
        @(Get-Calls | Where-Object { $_ -like 'IPPS*' }).Count | Should -Be 1
    }
    It 'reports a failed connection' {
        InModuleScope M365GapAssessment { $script:ConnectFails = $true }
        $r = InModuleScope M365GapAssessment { Start-ComplianceSession }
        $r.Ready | Should -BeFalse
        $r.Error | Should -BeLike '*Purview*boom*'
    }
}

Describe 'Stop-ExchangeSessions' {
    BeforeEach { Reset-Session }

    It 'does nothing when no session is open' {
        InModuleScope M365GapAssessment { Stop-ExchangeSessions }
        Get-Calls | Should -BeNullOrEmpty
    }
    It 'disconnects once even when both sessions are open' {
        InModuleScope M365GapAssessment { $null = Start-ExchangeSession; $null = Start-ComplianceSession; Stop-ExchangeSessions }
        @(Get-Calls | Where-Object { $_ -eq 'DISCONNECT' }).Count | Should -Be 1
    }
    It 'lets the next tenant connect again after a stop' {
        InModuleScope M365GapAssessment { $null = Start-ExchangeSession; Stop-ExchangeSessions; $null = Start-ExchangeSession }
        @(Get-Calls | Where-Object { $_ -like 'EXO*' }).Count | Should -Be 2
    }
}

Describe 'Assert-Cmdlet' {
    It 'throws a message naming the cmdlet and the hint when it is missing' {
        { InModuleScope M365GapAssessment { Assert-Cmdlet 'Get-NoSuchCmdletZzz' 'licence missing' } } | Should -Throw '*Get-NoSuchCmdletZzz*licence missing*'
    }
    It 'passes for a cmdlet that exists' {
        { InModuleScope M365GapAssessment { Assert-Cmdlet 'Get-Item' } } | Should -Not -Throw
    }
}
