#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Offline tests for Private/Get-DefenderO365Gaps.ps1 (Invoke-DefenderO365Checks) using fake Exchange cmdlets: no tenant, no session.

BeforeDiscovery {
    # Each case overrides one or more cmdlets of an otherwise healthy tenant and states the expected result for one finding.
    $script:Cases = @(
        # DFO-001 Safe Attachments
        @{ Name = 'DFO-001 gap: only an Allow-action policy';  Id = 'DFO-001'; Status = 'Gap';  Set = @{ 'Get-SafeAttachmentPolicy' = '[{"Name":"P","Enable":true,"Action":"Allow"}]' } }
        @{ Name = 'DFO-001 gap: blocking policy is disabled';  Id = 'DFO-001'; Status = 'Gap';  Set = @{ 'Get-SafeAttachmentPolicy' = '[{"Name":"P","Enable":false,"Action":"Block"}]' } }
        @{ Name = 'DFO-001 gap: custom Block policy with no assigning rule'; Id = 'DFO-001'; Status = 'Gap'; Set = @{ 'Get-SafeAttachmentPolicy' = '[{"Name":"Custom","Enable":true,"Action":"Block"}]'; 'Get-SafeAttachmentRule' = '[]' } }
        @{ Name = 'DFO-001 pass: custom Block policy assigned by an enabled rule'; Id = 'DFO-001'; Status = 'Pass'; Set = @{ 'Get-SafeAttachmentPolicy' = '[{"Name":"Custom","Enable":true,"Action":"Block"}]'; 'Get-SafeAttachmentRule' = '[{"State":"Enabled","SafeAttachmentPolicy":"Custom"}]' } }
        @{ Name = 'DFO-001 pass: built-in protection policy with Dynamic Delivery'; Id = 'DFO-001'; Status = 'Pass'; Set = @{} }
        # DFO-002 SharePoint / OneDrive / Teams
        @{ Name = 'DFO-002 gap: not enabled for SharePoint, OneDrive and Teams'; Id = 'DFO-002'; Status = 'Gap'; Set = @{ 'Get-AtpPolicyForO365' = '{"EnableATPForSPOTeamsODB":false,"EnableSafeDocs":true,"AllowSafeDocsOpen":false}' } }
        @{ Name = 'DFO-002 gap: Safe Documents click-through allowed'; Id = 'DFO-002'; Status = 'Gap'; Set = @{ 'Get-AtpPolicyForO365' = '{"EnableATPForSPOTeamsODB":true,"EnableSafeDocs":true,"AllowSafeDocsOpen":true}' } }
        @{ Name = 'DFO-002 pass';                              Id = 'DFO-002'; Status = 'Pass'; Set = @{} }
        # DFO-003 Safe Links settings
        @{ Name = 'DFO-003 gap: click-through allowed';        Id = 'DFO-003'; Status = 'Gap';  Set = @{ 'Get-SafeLinksPolicy' = '[{"Name":"P","EnableSafeLinksForEmail":true,"DoNotAllowClickThrough":false,"DoNotTrackUserClicks":false,"ScanUrls":true}]' } }
        @{ Name = 'DFO-003 gap: clicks not tracked';           Id = 'DFO-003'; Status = 'Gap';  Set = @{ 'Get-SafeLinksPolicy' = '[{"Name":"P","EnableSafeLinksForEmail":true,"DoNotAllowClickThrough":true,"DoNotTrackUserClicks":true,"ScanUrls":true}]' } }
        @{ Name = 'DFO-003 gap: URL scanning off';             Id = 'DFO-003'; Status = 'Gap';  Set = @{ 'Get-SafeLinksPolicy' = '[{"Name":"P","EnableSafeLinksForTeams":true,"DoNotAllowClickThrough":true,"DoNotTrackUserClicks":false,"ScanUrls":false}]' } }
        @{ Name = 'DFO-003 pass: a policy that is fully off is not judged'; Id = 'DFO-003'; Status = 'Pass'; Set = @{ 'Get-SafeLinksPolicy' = '[{"Name":"Off","EnableSafeLinksForEmail":false,"EnableSafeLinksForOffice":false,"EnableSafeLinksForTeams":false,"DoNotAllowClickThrough":false}]' } }
        # DFO-004 anti-malware
        @{ Name = 'DFO-004 gap: common attachment filter off'; Id = 'DFO-004'; Status = 'Gap';  Set = @{ 'Get-MalwareFilterPolicy' = '[{"Name":"Default","EnableFileFilter":false,"ZapEnabled":true}]' } }
        @{ Name = 'DFO-004 gap: malware ZAP off';              Id = 'DFO-004'; Status = 'Gap';  Set = @{ 'Get-MalwareFilterPolicy' = '[{"Name":"Default","EnableFileFilter":true,"ZapEnabled":false}]' } }
        # DFO-005 allow lists
        @{ Name = 'DFO-005 gap: allowed sender domains';       Id = 'DFO-005'; Status = 'Gap';  Set = @{ 'Get-HostedContentFilterPolicy' = '[{"Name":"Default","AllowedSenders":[],"AllowedSenderDomains":["partner.com"],"BulkThreshold":6,"HighConfidencePhishAction":"Quarantine"}]' } }
        @{ Name = 'DFO-005 gap: allowed senders';              Id = 'DFO-005'; Status = 'Gap';  Set = @{ 'Get-HostedContentFilterPolicy' = '[{"Name":"Default","AllowedSenders":["a@b.com"],"AllowedSenderDomains":[],"BulkThreshold":6,"HighConfidencePhishAction":"Quarantine"}]' } }
        # DFO-006 thresholds and actions
        @{ Name = 'DFO-006 gap: bulk threshold 8';             Id = 'DFO-006'; Status = 'Gap';  Set = @{ 'Get-HostedContentFilterPolicy' = '[{"Name":"Default","AllowedSenders":[],"AllowedSenderDomains":[],"BulkThreshold":8,"HighConfidencePhishAction":"Quarantine"}]' } }
        @{ Name = 'DFO-006 pass: bulk threshold exactly 6';    Id = 'DFO-006'; Status = 'Pass'; Set = @{ 'Get-HostedContentFilterPolicy' = '[{"Name":"Default","AllowedSenders":[],"AllowedSenderDomains":[],"BulkThreshold":6,"HighConfidencePhishAction":"Quarantine"}]' } }
        @{ Name = 'DFO-006 gap: phishing action not Quarantine'; Id = 'DFO-006'; Status = 'Gap'; Set = @{ 'Get-HostedContentFilterPolicy' = '[{"Name":"Default","AllowedSenders":[],"AllowedSenderDomains":[],"BulkThreshold":6,"HighConfidencePhishAction":"MoveToJmf"}]' } }
        @{ Name = 'DFO-006 gap: phishing ZAP off';             Id = 'DFO-006'; Status = 'Gap';  Set = @{ 'Get-HostedContentFilterPolicy' = '[{"Name":"Default","AllowedSenders":[],"AllowedSenderDomains":[],"BulkThreshold":6,"HighConfidencePhishAction":"Quarantine","PhishZapEnabled":false}]' } }
        # DFO-007 outbound notifications
        @{ Name = 'DFO-007 gap: blocked senders not notified'; Id = 'DFO-007'; Status = 'Gap';  Set = @{ 'Get-HostedOutboundSpamFilterPolicy' = '[{"Name":"Default","NotifyOutboundSpam":false}]' } }
        # DFO-008 preset policies
        @{ Name = 'DFO-008 gap: no preset rules';              Id = 'DFO-008'; Status = 'Gap';  Set = @{ 'Get-EOPProtectionPolicyRule' = '[]' } }
        @{ Name = 'DFO-008 gap: Standard preset disabled';     Id = 'DFO-008'; Status = 'Gap';  Set = @{ 'Get-EOPProtectionPolicyRule' = '[{"Name":"Standard Preset Security Policy","State":"Disabled"}]' } }
        @{ Name = 'DFO-008 pass: Strict preset enabled';       Id = 'DFO-008'; Status = 'Pass'; Set = @{ 'Get-EOPProtectionPolicyRule' = '[{"Name":"Strict Preset Security Policy","State":"Enabled"}]' } }
        @{ Name = 'DFO-008 pass: preset found only in the ATP rules'; Id = 'DFO-008'; Status = 'Pass'; Set = @{ 'Get-EOPProtectionPolicyRule' = '[]'; 'Get-ATPProtectionPolicyRule' = '[{"Name":"Strict Preset Security Policy","State":"Enabled"}]' } }
        # DFO-009 / DFO-010 mail flow rules
        @{ Name = 'DFO-009 gap: enabled rule sets SCL -1';     Id = 'DFO-009'; Status = 'Gap';  Set = @{ 'Get-TransportRule' = '[{"Name":"Bypass","State":"Enabled","SetSCL":-1}]' } }
        @{ Name = 'DFO-009 pass: disabled bypass rule';        Id = 'DFO-009'; Status = 'Pass'; Set = @{ 'Get-TransportRule' = '[{"Name":"Bypass","State":"Disabled","SetSCL":-1}]' } }
        @{ Name = 'DFO-009 pass: rule sets SCL 0';             Id = 'DFO-009'; Status = 'Pass'; Set = @{ 'Get-TransportRule' = '[{"Name":"Other","State":"Enabled","SetSCL":0}]' } }
        @{ Name = 'DFO-010 gap: rule redirects mail';          Id = 'DFO-010'; Status = 'Gap';  Set = @{ 'Get-TransportRule' = '[{"Name":"Fwd","State":"Enabled","RedirectMessageTo":["x@y.com"]}]' } }
        @{ Name = 'DFO-010 gap: rule blind-copies mail';       Id = 'DFO-010'; Status = 'Gap';  Set = @{ 'Get-TransportRule' = '[{"Name":"Bcc","State":"Enabled","BlindCopyTo":["x@y.com"]}]' } }
        @{ Name = 'DFO-010 pass: no rules';                    Id = 'DFO-010'; Status = 'Pass'; Set = @{} }
        # DFO-011 connection filter
        @{ Name = 'DFO-011 gap: IP allow list';                Id = 'DFO-011'; Status = 'Gap';  Set = @{ 'Get-HostedConnectionFilterPolicy' = '[{"Name":"Default","IPAllowList":["10.0.0.1"],"EnableSafeList":false}]' } }
        @{ Name = 'DFO-011 gap: safe list enabled';            Id = 'DFO-011'; Status = 'Gap';  Set = @{ 'Get-HostedConnectionFilterPolicy' = '[{"Name":"Default","IPAllowList":[],"EnableSafeList":true}]' } }
        # DFO-012..014 user-facing
        @{ Name = 'DFO-012 gap: external sender tag off';      Id = 'DFO-012'; Status = 'Gap';  Set = @{ 'Get-ExternalInOutlook' = '{"Enabled":false}' } }
        @{ Name = 'DFO-013 gap: Teams ZAP off';                Id = 'DFO-013'; Status = 'Gap';  Set = @{ 'Get-TeamsProtectionPolicy' = '{"ZapEnabled":false}' } }
        @{ Name = 'DFO-014 gap: reporting to Microsoft off';   Id = 'DFO-014'; Status = 'Gap';  Set = @{ 'Get-ReportSubmissionPolicy' = '{"EnableReportToMicrosoft":false}' } }
        @{ Name = 'DFO-014 pass: reporting on';                Id = 'DFO-014'; Status = 'Pass'; Set = @{} }
        @{ Name = 'DFO-014 NotAssessed (not a pass): setting not returned'; Id = 'DFO-014'; Status = 'NotAssessed'; Set = @{ 'Get-ReportSubmissionPolicy' = '{"Name":"DefaultReportSubmissionPolicy"}' } }
        @{ Name = 'DFO-014 NotAssessed (not a pass): no policy object returned'; Id = 'DFO-014'; Status = 'NotAssessed'; Set = @{ 'Get-ReportSubmissionPolicy' = '[]' } }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeCmdlets.ps1')

    function script:J($Json) { $Json | ConvertFrom-Json }

    # A tenant with every protection in place; tests override single cmdlets.
    function script:Get-Healthy {
        @{
            'Get-SafeAttachmentPolicy'           = (J '[{"Name":"Built-In Protection Policy","Enable":true,"Action":"DynamicDelivery"}]')
            'Get-AtpPolicyForO365'               = (J '{"EnableATPForSPOTeamsODB":true,"EnableSafeDocs":true,"AllowSafeDocsOpen":false}')
            'Get-SafeLinksPolicy'                = (J '[{"Name":"P","EnableSafeLinksForEmail":true,"EnableSafeLinksForOffice":true,"EnableSafeLinksForTeams":true,"DoNotAllowClickThrough":true,"DoNotTrackUserClicks":false,"ScanUrls":true}]')
            'Get-MalwareFilterPolicy'            = (J '[{"Name":"Default","EnableFileFilter":true,"ZapEnabled":true}]')
            'Get-HostedContentFilterPolicy'      = (J '[{"Name":"Default","AllowedSenders":[],"AllowedSenderDomains":[],"BulkThreshold":6,"HighConfidencePhishAction":"Quarantine","PhishZapEnabled":true,"SpamZapEnabled":true}]')
            'Get-HostedOutboundSpamFilterPolicy' = (J '[{"Name":"Default","NotifyOutboundSpam":true}]')
            'Get-EOPProtectionPolicyRule'        = (J '[{"Name":"Standard Preset Security Policy","State":"Enabled"}]')
            'Get-TransportRule'                  = (J '[]')
            'Get-HostedConnectionFilterPolicy'   = (J '[{"Name":"Default","IPAllowList":[],"EnableSafeList":false}]')
            'Get-ExternalInOutlook'              = (J '{"Enabled":true}')
            'Get-TeamsProtectionPolicy'          = (J '{"ZapEnabled":true}')
            'Get-ReportSubmissionPolicy'         = (J '{"EnableReportToMicrosoft":true}')
        }
    }

    function script:Invoke-Checks {
        param([hashtable]$Set = @{})
        $data = Get-Healthy
        foreach ($k in $Set.Keys) { $data[$k] = if ($Set[$k] -is [string]) { J $Set[$k] } else { $Set[$k] } }
        Invoke-WithCmdlets -Data $data -Command 'Invoke-DefenderO365Checks'
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Defender for Office 365 checks' {
    It '<Name>' -ForEach $script:Cases {
        (Invoke-Checks -Set $Set)[$Id].Status | Should -Be $Status
    }

    It 'a healthy tenant passes all 14 checks, each reported exactly once' {
        $r = Invoke-Checks
        $r.Keys.Count | Should -Be 14
        ($r.Values | Where-Object Status -ne 'Pass') | Should -BeNullOrEmpty
    }

    It 'DFO-014 names the properties it saw when the setting is missing, to help diagnose it' {
        $f = (Invoke-Checks -Set @{ 'Get-ReportSubmissionPolicy' = '{"Name":"DefaultReportSubmissionPolicy","Other":1}' })['DFO-014']
        $f.Detail | Should -BeLike '*Properties seen: *Name*Other*'
    }

    It 'Pass details say what was evaluated instead of repeating the Gap description' {
        $r = Invoke-Checks
        foreach ($id in 'DFO-003', 'DFO-004', 'DFO-005', 'DFO-006', 'DFO-010', 'DFO-011') {
            $r[$id].Status | Should -Be 'Pass'
            $r[$id].Detail | Should -BeLike '*were checked*' -Because "$id should report how many items were evaluated"
        }
    }

    It 'lists the offending policy in the affected objects' {
        $f = (Invoke-Checks -Set @{ 'Get-HostedContentFilterPolicy' = '[{"Name":"Custom","AllowedSenders":[],"AllowedSenderDomains":["partner.com"],"BulkThreshold":6,"HighConfidencePhishAction":"Quarantine"}]' })['DFO-005']
        $f.AffectedObjects[0] | Should -BeLike 'Custom*partner.com*'
    }

    Context 'failures stay isolated' {
        It 'a refused cmdlet makes only its own check NotAssessed' {
            $r = Invoke-Checks -Set @{ 'Get-MalwareFilterPolicy' = { throw 'access denied' } }
            $r['DFO-004'].Status | Should -Be 'NotAssessed'
            $r['DFO-004'].Detail | Should -BeLike '*access denied*'
            $r['DFO-005'].Status | Should -Be 'Pass'
        }
        It 'a cmdlet that is not available is NotAssessed with a licence hint' {
            $data = Get-Healthy
            $data.Remove('Get-SafeAttachmentPolicy')          # not defined at all, like an unlicensed tenant
            $r = Invoke-WithCmdlets -Data $data -Command 'Invoke-DefenderO365Checks'
            $r['DFO-001'].Status | Should -Be 'NotAssessed'
            $r['DFO-001'].Detail | Should -BeLike '*not available*'
            $r['DFO-002'].Status | Should -Be 'Pass'
        }
    }
}

Describe 'Get-DefenderO365Gaps session handling' {
    It 'reports all 14 checks NotAssessed with the reason when Exchange cannot be reached' {
        Set-FakeCmdlets -Data @{ 'Connect-ExchangeOnline' = { throw 'sign-in cancelled' } }
        $r = InModuleScope M365GapAssessment {
            # Stand-ins so the session helper sees the module as installed and uses the fake Connect-ExchangeOnline.
            function script:Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } }
            function script:Import-Module { }
            $script:ExchangeSessionOpen = $false
            try { Get-DefenderO365Gaps 3>$null } finally { Remove-Item Function:\Get-Module, Function:\Import-Module -ErrorAction SilentlyContinue }
        }
        @($r).Count | Should -Be 14
        ($r | Where-Object Status -ne 'NotAssessed') | Should -BeNullOrEmpty
        $r[0].Detail | Should -BeLike '*sign-in cancelled*'
    }
}
