#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# CIS Microsoft 365 Foundations view (-CisView): findings regrouped by recommendation number and benchmark section.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    $script:Support = Join-Path $PSScriptRoot 'Support/TestSupport.ps1'

    # Minimal findings: only the properties the view reads.
    function script:F($Id, $Status, [string[]]$Cis, $Name = "Name of $Id") {
        [pscustomobject]@{ FindingId = $Id; Name = $Name; Status = $Status; CisControl = $Cis }
    }
    function script:View([object[]]$Findings) {
        InModuleScope M365GapAssessment -Parameters @{ X = $Findings } { Get-CisView -Findings $X }
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Get-CisView grouping' {
    It 'returns nothing when no finding has a CIS reference' {
        View @((F 'A-1' 'Gap' @()), (F 'A-2' 'Pass' $null)) | Should -BeNullOrEmpty
    }

    It 'lists a finding under every CIS recommendation it maps to' {
        $v = View @(F 'ENT-POL-003' 'Gap' @('5.1.2.2', '5.1.2.3'))
        @($v.Sections[0].Items.Ref) -join ',' | Should -Be '5.1.2.2,5.1.2.3'
        $v.Total | Should -Be 2
    }

    It 'combines findings that share one recommendation' {
        $v = View @((F 'X-1' 'Pass' @('5.2.3.1')), (F 'X-2' 'Pass' @('5.2.3.1')))
        $v.Total | Should -Be 1
        @($v.Sections[0].Items[0].Findings).Count | Should -Be 2
    }

    It 'orders recommendation numbers numerically, not alphabetically' {
        $v = View @((F 'A' 'Pass' @('5.2.2.10')), (F 'B' 'Pass' @('5.2.2.2')), (F 'C' 'Pass' @('5.2.2.3')), (F 'D' 'Pass' @('5.10.1')), (F 'E' 'Pass' @('5.2.1')))
        @($v.Sections[0].Items.Ref) -join ',' | Should -Be '5.2.1,5.2.2.2,5.2.2.3,5.2.2.10,5.10.1'
    }

    It 'orders sections numerically and gives each its benchmark title' {
        $v = View @((F 'A' 'Pass' @('8.1.1')), (F 'B' 'Pass' @('2.1.1')), (F 'C' 'Pass' @('10.1')), (F 'D' 'Pass' @('5.1')))
        @($v.Sections.Number) -join ',' | Should -Be '2,5,8,10'
        ($v.Sections | Where-Object Number -eq '5').Title | Should -Be 'Microsoft Entra admin center'
        ($v.Sections | Where-Object Number -eq '8').Title | Should -Be 'Microsoft Teams admin center'
        ($v.Sections | Where-Object Number -eq '10').Title | Should -Be 'Section 10'
    }
}

Describe 'Get-CisView status roll-up' {
    It 'worst status wins: Gap > Not assessed > Accepted > Pass' {
        (View @((F 'A' 'Pass' @('1.1')), (F 'B' 'Gap' @('1.1')))).Sections[0].Items[0].Status | Should -Be 'Gap'
        (View @((F 'A' 'Pass' @('1.1')), (F 'B' 'NotAssessed' @('1.1')))).Sections[0].Items[0].Status | Should -Be 'Not assessed'
        (View @((F 'A' 'Pass' @('1.1')), (F 'B' 'Accepted' @('1.1')))).Sections[0].Items[0].Status | Should -Be 'Accepted'
        (View @((F 'A' 'Pass' @('1.1')), (F 'B' 'Pass' @('1.1')))).Sections[0].Items[0].Status | Should -Be 'Pass'
    }

    It 'counts Pass (including Accepted), Gap and Not assessed per section' {
        $v = View @((F 'A' 'Pass' @('5.1')), (F 'B' 'Accepted' @('5.2')), (F 'C' 'Gap' @('5.3')), (F 'D' 'Gap' @('5.4')), (F 'E' 'NotAssessed' @('5.5')), (F 'F' 'Pass' @('6.1')))
        $s5 = $v.Sections | Where-Object Number -eq '5'
        $s5.Items.Count | Should -Be 5
        $s5.Pass | Should -Be 2
        $s5.Gap | Should -Be 2
        $s5.NotAssessed | Should -Be 1
        ($v.Sections | Where-Object Number -eq '6').Pass | Should -Be 1
    }
}

Describe 'Rendering' {
    BeforeAll {
        $script:Hostile = '<script>alert(1)</script> | pipe'
        $view = View @((F 'A-1' 'Gap' @('5.2.2.3') $script:Hostile), (F 'B-1' 'Pass' @('6.1.1')))
        $script:Md = (InModuleScope M365GapAssessment -Parameters @{ V = $view } { Get-CisViewMarkdown -View $V }) -join "`n"
        $script:Html = InModuleScope M365GapAssessment -Parameters @{ V = $view } { Get-CisViewHtml -View $V }
    }
    It 'Markdown has the heading, the section summary and a table per section' {
        $script:Md | Should -BeLike '*## CIS Microsoft 365 Foundations View*'
        $script:Md | Should -BeLike '*| 5 Microsoft Entra admin center | 1 | 0 | 1 | 0 |*'
        $script:Md | Should -BeLike '*### 6 Exchange admin center*'
        $script:Md | Should -BeLike '*| 5.2.2.3 | Gap | A-1 *'
    }
    It 'labels the column "Issue checked" and explains that Pass means the issue was not found' {
        $script:Md | Should -BeLike '*| CIS | Status | Issue checked |*'
        $script:Md | Should -BeLike '*Pass** means that issue was not found*'
        $script:Html | Should -BeLike '*<th>Issue checked</th>*'
        $script:Html | Should -BeLike '*Pass means that issue was not found*'
    }
    It 'Markdown says the view is not a score against the whole benchmark' {
        $script:Md | Should -BeLike '*not*a score against the whole benchmark*'
    }
    It 'Markdown escapes pipes so a name cannot break the table' {
        $script:Md | Should -BeLike '*\| pipe*'
    }
    It 'HTML encodes finding names (no script injection)' {
        $script:Html | Should -Not -BeLike '*<script>*'
        $script:Html | Should -BeLike '*&lt;script&gt;*'
    }
    It 'HTML marks gaps and passes with the report status classes' {
        $script:Html | Should -BeLike '*class="s-Gap">Gap*'
        $script:Html | Should -BeLike '*class="s-Pass">Pass*'
    }
}

Describe 'Reports with -CisView' {
    BeforeAll {
        $a = InModuleScope M365GapAssessment -Parameters @{ S = $script:Support } {
            . $S
            $x = New-MockAssessment
            $x.Findings = @((New-Finding -Id 'ENT-CA-004' -Status Gap -AffectedObjects @('p')), (New-Finding -Id 'ENT-AUTH-007' -Status Pass), (New-Finding -Id 'SSC-001' -Status Pass))
            $x
        }
        $script:On = Join-Path $TestDrive 'on'
        $script:Off = Join-Path $TestDrive 'off'
        $null = Export-M365GapReport -Assessment $a -ExportPath $script:On -Format Markdown, HTML -CisView
        $null = Export-M365GapReport -Assessment $a -ExportPath $script:Off -Format Markdown, HTML
        $script:JsonA = $a
    }
    It 'includes the CIS view in Markdown and HTML when requested' {
        (Get-Content -Raw (Join-Path $script:On 'M365_Security_Gap_Assessment.md')) | Should -BeLike '*## CIS Microsoft 365 Foundations View*'
        (Get-Content -Raw (Join-Path $script:On 'M365_Security_Gap_Assessment.html')) | Should -BeLike '*CIS Microsoft 365 Foundations view*'
    }
    It 'maps the real finding ENT-CA-004 into section 5' {
        (Get-Content -Raw (Join-Path $script:On 'M365_Security_Gap_Assessment.md')) | Should -BeLike '*### 5 Microsoft Entra admin center*'
    }
    It 'lets wide appendix tables scroll inside their box instead of spilling off narrow screens' {
        (Get-Content -Raw (Join-Path $script:On 'M365_Security_Gap_Assessment.html')) | Should -Match 'details \.body\{[^}]*overflow-x:auto'
    }
    It 'leaves the default reports unchanged' {
        (Get-Content -Raw (Join-Path $script:Off 'M365_Security_Gap_Assessment.md')) | Should -Not -BeLike '*CIS Microsoft 365 Foundations View*'
        (Get-Content -Raw (Join-Path $script:Off 'M365_Security_Gap_Assessment.html')) | Should -Not -BeLike '*CIS Microsoft 365 Foundations view*'
    }
    It 'says so when no finding has a CIS reference' {
        $none = InModuleScope M365GapAssessment -Parameters @{ S = $script:Support } { . $S; $x = New-MockAssessment; $x.Findings = @((New-Finding -Id 'SSC-001' -Status Pass)); $x }
        $dir = Join-Path $TestDrive 'none'
        $null = Export-M365GapReport -Assessment $none -ExportPath $dir -Format Markdown -CisView
        (Get-Content -Raw (Join-Path $dir 'M365_Security_Gap_Assessment.md')) | Should -BeLike '*No finding in this assessment carries a CIS reference*'
    }
    It 'can be added when re-rendering saved JSON with Convert-M365Report' {
        $jsonDir = Join-Path $TestDrive 'convert'
        $null = Export-M365GapReport -Assessment $script:JsonA -ExportPath $jsonDir -Format JSON
        $out = @(Convert-M365Report -Path (Join-Path $jsonDir 'AssessmentFindings.json') -Format Markdown -CisView)
        Get-Content -Raw $out[0] | Should -BeLike '*## CIS Microsoft 365 Foundations View*'
    }
    It 'is exposed as a switch on the review cmdlet' {
        (Get-Command Invoke-M365SecurityReview).Parameters['CisView'].ParameterType.Name | Should -Be 'SwitchParameter'
    }
}

Describe 'The real control mapping' {
    It 'places every CIS reference in a known benchmark section, with no reference lost' {
        $mapping = (Get-Content -Raw (Join-Path $PSScriptRoot '../M365GapAssessment/Data/ControlMapping.json') | ConvertFrom-Json).controls
        $findings = @($mapping | Where-Object { $_.cis } | ForEach-Object { F $_.id 'Gap' @($_.cis) })
        $expected = @($findings.CisControl | Sort-Object -Unique)
        $v = View $findings
        @($v.Sections.Items.Ref | Sort-Object -Unique).Count | Should -Be $expected.Count
        foreach ($s in $v.Sections) { $s.Title | Should -Not -BeLike 'Section *' -Because "section $($s.Number) has no benchmark title" }
    }
}
