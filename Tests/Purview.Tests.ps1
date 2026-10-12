#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Offline tests for Private/Get-PurviewGaps.ps1 (Invoke-PurviewChecks) using fake compliance cmdlets: no tenant, no session.

BeforeDiscovery {
    $script:Cases = @(
        @{ Name = 'PUR-001 gap: unified audit log off';           Id = 'PUR-001'; Status = 'Gap';  Set = @{ 'Get-AdminAuditLogConfig' = '{"UnifiedAuditLogIngestionEnabled":false}' } }
        @{ Name = 'PUR-001 pass: unified audit log on';           Id = 'PUR-001'; Status = 'Pass'; Set = @{} }
        @{ Name = 'PUR-002 gap: no DLP policies';                 Id = 'PUR-002'; Status = 'Gap';  Set = @{ 'Get-DlpCompliancePolicy' = '[]' } }
        @{ Name = 'PUR-002 gap: only test mode without notifications'; Id = 'PUR-002'; Status = 'Gap'; Set = @{ 'Get-DlpCompliancePolicy' = '[{"Name":"D","Enabled":true,"Mode":"TestWithoutNotifications","Workload":"Exchange"}]' } }
        @{ Name = 'PUR-002 gap: only test mode with notifications';    Id = 'PUR-002'; Status = 'Gap'; Set = @{ 'Get-DlpCompliancePolicy' = '[{"Name":"D","Enabled":true,"Mode":"TestWithNotifications","Workload":"Exchange"}]' } }
        @{ Name = 'PUR-002 gap: policy disabled';                 Id = 'PUR-002'; Status = 'Gap';  Set = @{ 'Get-DlpCompliancePolicy' = '[{"Name":"D","Enabled":false,"Mode":"Enable","Workload":"Exchange"}]' } }
        @{ Name = 'PUR-002 pass: an enforcing policy';            Id = 'PUR-002'; Status = 'Pass'; Set = @{} }
        @{ Name = 'PUR-003 gap: Exchange only';                   Id = 'PUR-003'; Status = 'Gap';  Set = @{ 'Get-DlpCompliancePolicy' = '[{"Name":"D","Enabled":true,"Mode":"Enable","Workload":"Exchange"}]' } }
        @{ Name = 'PUR-003 gap: Teams missing';                   Id = 'PUR-003'; Status = 'Gap';  Set = @{ 'Get-DlpCompliancePolicy' = '[{"Name":"D","Enabled":true,"Mode":"Enable","Workload":"Exchange, SharePoint, OneDriveForBusiness"}]' } }
        @{ Name = 'PUR-003 pass: workloads split across policies'; Id = 'PUR-003'; Status = 'Pass'; Set = @{ 'Get-DlpCompliancePolicy' = '[{"Name":"A","Enabled":true,"Mode":"Enable","Workload":"Exchange, SharePoint"},{"Name":"B","Enabled":true,"Mode":"Enable","Workload":"OneDriveForBusiness, Teams"}]' } }
        @{ Name = 'PUR-003 gap: a test-mode policy does not count toward coverage'; Id = 'PUR-003'; Status = 'Gap'; Set = @{ 'Get-DlpCompliancePolicy' = '[{"Name":"A","Enabled":true,"Mode":"Enable","Workload":"Exchange"},{"Name":"B","Enabled":true,"Mode":"TestWithNotifications","Workload":"SharePoint, OneDriveForBusiness, Teams"}]' } }
        @{ Name = 'PUR-004 gap: no label policy';                 Id = 'PUR-004'; Status = 'Gap';  Set = @{ 'Get-LabelPolicy' = '[]' } }
        @{ Name = 'PUR-004 gap: label policy publishes no label'; Id = 'PUR-004'; Status = 'Gap';  Set = @{ 'Get-LabelPolicy' = '[{"Name":"LP","Enabled":true,"Labels":[]}]' } }
        @{ Name = 'PUR-004 gap: the only label policy is disabled'; Id = 'PUR-004'; Status = 'Gap'; Set = @{ 'Get-LabelPolicy' = '[{"Name":"LP","Enabled":false,"Labels":["l1"]}]' } }
        @{ Name = 'PUR-004 pass: published labels';               Id = 'PUR-004'; Status = 'Pass'; Set = @{} }
        @{ Name = 'PUR-005 gap: no retention policy';             Id = 'PUR-005'; Status = 'Gap';  Set = @{ 'Get-RetentionCompliancePolicy' = '[]' } }
        @{ Name = 'PUR-005 gap: retention policy disabled';       Id = 'PUR-005'; Status = 'Gap';  Set = @{ 'Get-RetentionCompliancePolicy' = '[{"Name":"R","Enabled":false}]' } }
        @{ Name = 'PUR-005 pass: enabled retention policy';       Id = 'PUR-005'; Status = 'Pass'; Set = @{} }
        @{ Name = 'PUR-006 gap: no insider risk policy';          Id = 'PUR-006'; Status = 'Gap';  Set = @{ 'Get-InsiderRiskPolicy' = '[]' } }
        @{ Name = 'PUR-006 pass: an insider risk policy';         Id = 'PUR-006'; Status = 'Pass'; Set = @{} }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeCmdlets.ps1')

    function script:J($Json) { $Json | ConvertFrom-Json }

    function script:Get-Healthy {
        @{
            'Get-AdminAuditLogConfig'      = (J '{"UnifiedAuditLogIngestionEnabled":true}')
            'Get-DlpCompliancePolicy'      = (J '[{"Name":"DLP","Enabled":true,"Mode":"Enable","Workload":"Exchange, SharePoint, OneDriveForBusiness, Teams"}]')
            'Get-LabelPolicy'              = (J '[{"Name":"LP","Enabled":true,"Labels":["l1","l2"]}]')
            'Get-RetentionCompliancePolicy' = (J '[{"Name":"R","Enabled":true}]')
            'Get-InsiderRiskPolicy'        = (J '[{"Name":"IR"}]')
        }
    }

    function script:Invoke-Checks {
        param([hashtable]$Set = @{}, [string[]]$Without = @())
        $data = Get-Healthy
        foreach ($k in $Set.Keys) { $data[$k] = if ($Set[$k] -is [string]) { J $Set[$k] } else { $Set[$k] } }
        foreach ($k in $Without) { $data.Remove($k) }
        Invoke-WithCmdlets -Data $data -Command 'Invoke-PurviewChecks'
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Purview checks' {
    It '<Name>' -ForEach $script:Cases {
        (Invoke-Checks -Set $Set)[$Id].Status | Should -Be $Status
    }

    It 'a healthy tenant passes all 6 checks, each reported once' {
        $r = Invoke-Checks
        $r.Keys.Count | Should -Be 6
        ($r.Values | Where-Object Status -ne 'Pass') | Should -BeNullOrEmpty
    }

    It 'PUR-003 names exactly the workloads that are missing' {
        $f = (Invoke-Checks -Set @{ 'Get-DlpCompliancePolicy' = '[{"Name":"D","Enabled":true,"Mode":"Enable","Workload":"Exchange, Teams"}]' })['PUR-003']
        $f.AffectedCount | Should -Be 2
        ($f.AffectedObjects -join ' ') | Should -BeLike '*SharePoint*'
        ($f.AffectedObjects -join ' ') | Should -BeLike '*OneDrive*'
        ($f.AffectedObjects -join ' ') | Should -Not -BeLike '*Exchange*'
    }

    It 'PUR-002 lists the policies that are not enforcing' {
        $f = (Invoke-Checks -Set @{ 'Get-DlpCompliancePolicy' = '[{"Name":"Pilot","Enabled":true,"Mode":"TestWithNotifications","Workload":"Exchange"}]' })['PUR-002']
        $f.AffectedObjects[0] | Should -BeLike 'Pilot*TestWithNotifications*'
    }

    Context 'failures stay isolated' {
        It 'a refused DLP call makes only the DLP checks NotAssessed' {
            $r = Invoke-Checks -Set @{ 'Get-DlpCompliancePolicy' = { throw 'access denied' } }
            $r['PUR-002'].Status | Should -Be 'NotAssessed'
            $r['PUR-003'].Status | Should -Be 'NotAssessed'
            $r['PUR-002'].Detail | Should -BeLike '*access denied*'
            $r['PUR-001'].Status | Should -Be 'Pass'
            $r['PUR-004'].Status | Should -Be 'Pass'
        }
        It 'insider risk without a premium licence (cmdlet absent) is NotAssessed with a licence hint, not a Gap' {
            $r = Invoke-Checks -Without 'Get-InsiderRiskPolicy'
            $r['PUR-006'].Status | Should -Be 'NotAssessed'
            $r['PUR-006'].Detail | Should -BeLike '*premium licence*'
            $r['PUR-006'].Detail | Should -BeLike '*Global Reader*'   # the role can be the cause, not only the licence
        }
    }
}

Describe 'Get-PurviewGaps session handling' {
    It 'reports all 6 checks NotAssessed with the reason when the compliance session cannot be opened' {
        Set-FakeCmdlets -Data @{ 'Connect-IPPSSession' = { throw 'sign-in cancelled' } }
        $r = InModuleScope M365GapAssessment {
            function script:Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } }
            function script:Import-Module { }
            $script:ComplianceSessionOpen = $false
            try { Get-PurviewGaps 3>$null } finally { Remove-Item Function:\Get-Module, Function:\Import-Module -ErrorAction SilentlyContinue }
        }
        @($r).Count | Should -Be 6
        ($r | Where-Object Status -ne 'NotAssessed') | Should -BeNullOrEmpty
        $r[0].Detail | Should -BeLike '*sign-in cancelled*'
    }
}
