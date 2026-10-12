#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Per-finding evidence files (-IncludeEvidence): one CSV per Gap finding with the FULL list of affected items, linked from the
# reports, safe to open in a spreadsheet, and protected like the reports themselves.

BeforeDiscovery {
    $script:SafeValueCases = @(
        @{ Name = 'plain text is unchanged';             In = 'alice@contoso.com';           Out = 'alice@contoso.com' }
        @{ Name = 'leading = is neutralised';            In = '=HYPERLINK("http://x","y")';  Out = '''=HYPERLINK("http://x","y")' }
        @{ Name = 'leading + is neutralised';            In = '+441234567';                   Out = '''+441234567' }
        @{ Name = 'leading - is neutralised';            In = '-2+3';                         Out = '''-2+3' }
        @{ Name = 'leading @ is neutralised';            In = '@SUM(A1)';                     Out = '''@SUM(A1)' }
        @{ Name = 'leading tab is neutralised';          In = "`t=cmd";                       Out = "'`t=cmd" }
        @{ Name = 'an equals sign later is harmless';    In = 'a=b';                          Out = 'a=b' }
        @{ Name = 'line breaks are flattened';           In = "line1`r`nline2";               Out = 'line1 line2' }
    )
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    $script:Guid = '11111111-2222-3333-4444-555555555555'
    $script:Support = Join-Path $PSScriptRoot 'Support/TestSupport.ps1'

    # Assessment with: a Gap with 60 items (more than the 25 shown in reports) including a formula-injection name, a Gap with
    # one item, a Gap with no items, a Pass, and a NotAssessed.
    function script:New-EvidenceAssessment {
        InModuleScope M365GapAssessment -Parameters @{ G = $script:Guid; S = $script:Support } {
            . $S   # New-MockAssessment lives in the test support file
            $many = @(1..59 | ForEach-Object { "user$_@contoso.com" }) + '=HYPERLINK("http://evil.example","click")'
            $a = New-MockAssessment -TenantId $G
            $a.Findings = @(
                (New-Finding -Id 'ENT-USR-003' -Status Gap -AffectedObjects $many -Detail 'Users without MFA')
                (New-Finding -Id 'ENT-POL-003' -Status Gap -AffectedObjects @('Users can register applications'))
                (New-Finding -Id 'ENT-CA-004' -Status Gap -Detail 'No affected objects, only a description')
                (New-Finding -Id 'SSC-001' -Status Pass)
                (New-Finding -Id 'DEF-DEV-001' -Status NotAssessed -Detail 'No devices')
            )
            $a
        }
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-SafeCsvValue' {
    It '<Name>' -ForEach $script:SafeValueCases {
        InModuleScope M365GapAssessment -Parameters @{ V = $In } { ConvertTo-SafeCsvValue $V } | Should -BeExactly $Out
    }
    It 'turns null into an empty string' {
        InModuleScope M365GapAssessment { ConvertTo-SafeCsvValue $null } | Should -BeExactly ''
    }
}

Describe 'Write-EvidenceFiles' {
    BeforeAll {
        $script:Folder = Join-Path $TestDrive 'run'
        $null = New-Item -ItemType Directory -Path $script:Folder
        $script:A = New-EvidenceAssessment
        $script:Written = @(InModuleScope M365GapAssessment -Parameters @{ A = $script:A; F = $script:Folder } { Write-EvidenceFiles -Assessment $A -Folder $F })
    }

    It 'writes one CSV per Gap finding that has affected items, plus an index' {
        ($script:Written | ForEach-Object { Split-Path $_ -Leaf } | Sort-Object) -join ',' | Should -Be '_index.csv,ENT-POL-003.csv,ENT-USR-003.csv'
    }
    It 'writes nothing for a Gap with no items, a Pass or a NotAssessed finding' {
        foreach ($id in 'ENT-CA-004', 'SSC-001', 'DEF-DEV-001') { Test-Path (Join-Path $script:Folder "evidence/$id.csv") | Should -BeFalse }
    }
    It 'keeps every item, not just the 25 shown in the reports' {
        @(Import-Csv (Join-Path $script:Folder 'evidence/ENT-USR-003.csv')).Count | Should -Be 60
    }
    It 'records the relative path on the finding' {
        ($script:A.Findings | Where-Object FindingId -eq 'ENT-USR-003').EvidenceFile | Should -Be 'evidence/ENT-USR-003.csv'
        ($script:A.Findings | Where-Object FindingId -eq 'SSC-001').EvidenceFile | Should -BeNullOrEmpty
    }
    It 'neutralises spreadsheet formulas in the data' {
        $items = (Import-Csv (Join-Path $script:Folder 'evidence/ENT-USR-003.csv')).AffectedItem
        ($items | Where-Object { $_ -like '*HYPERLINK*' }) | Should -BeExactly '''=HYPERLINK("http://evil.example","click")'
        ($items | Where-Object { $_ -match '^[=+\-@]' }) | Should -BeNullOrEmpty
    }
    It 'has the expected columns' {
        (Import-Csv (Join-Path $script:Folder 'evidence/ENT-USR-003.csv'))[0].PSObject.Properties.Name -join ',' | Should -Be 'FindingId,Severity,AffectedItem'
    }
    It 'indexes each file with its count and framework references' {
        $idx = @(Import-Csv (Join-Path $script:Folder 'evidence/_index.csv'))
        $idx.Count | Should -Be 2
        ($idx | Where-Object FindingId -eq 'ENT-USR-003').AffectedCount | Should -Be 60
        ($idx | Where-Object FindingId -eq 'ENT-USR-003').File | Should -Be 'evidence/ENT-USR-003.csv'
        ($idx | Where-Object FindingId -eq 'ENT-USR-003').NistCsf | Should -Not -BeNullOrEmpty
    }
    It 'never writes the tenant ID into an evidence file' {
        foreach ($f in $script:Written) { Get-Content -Raw $f | Should -Not -BeLike "*$script:Guid*" }
    }
    It 'creates no evidence folder when there is nothing to record' {
        $empty = Join-Path $TestDrive 'empty'
        $null = New-Item -ItemType Directory -Path $empty
        $a = InModuleScope M365GapAssessment -Parameters @{ S = $script:Support } { . $S; $x = New-MockAssessment; $x.Findings = @((New-Finding -Id 'SSC-001' -Status Pass)); $x }
        @(InModuleScope M365GapAssessment -Parameters @{ A = $a; F = $empty } { Write-EvidenceFiles -Assessment $A -Folder $F }).Count | Should -Be 0
        Test-Path (Join-Path $empty 'evidence') | Should -BeFalse
    }
}

Describe 'Export-M365GapReport -IncludeEvidence' {
    BeforeAll {
        $script:A = New-EvidenceAssessment
        $script:With = Join-Path $TestDrive 'with'
        $script:Without = Join-Path $TestDrive 'without'
        $script:WithFiles = @(Export-M365GapReport -Assessment $script:A -ExportPath $script:With -Format JSON, Markdown, HTML -IncludeEvidence)
        $script:B = New-EvidenceAssessment
        $null = Export-M365GapReport -Assessment $script:B -ExportPath $script:Without -Format JSON, Markdown, HTML
        $script:Md = Get-Content -Raw (Join-Path $script:With 'M365_Security_Gap_Assessment.md')
        $script:Html = Get-Content -Raw (Join-Path $script:With 'M365_Security_Gap_Assessment.html')
    }

    It 'returns the evidence files among the written files' {
        ($script:WithFiles | Where-Object { $_ -like '*evidence*ENT-USR-003.csv' }) | Should -Not -BeNullOrEmpty
    }
    It 'records EvidenceFile in the JSON' {
        $json = Get-Content -Raw (Join-Path $script:With 'AssessmentFindings.json') | ConvertFrom-Json
        ($json.Findings | Where-Object FindingId -eq 'ENT-USR-003').EvidenceFile | Should -Be 'evidence/ENT-USR-003.csv'
    }
    It 'links the evidence file from the Markdown report and points the "more" line at it' {
        $script:Md | Should -Match ([regex]::Escape('[evidence/ENT-USR-003.csv](evidence/ENT-USR-003.csv)'))
        $script:Md | Should -BeLike '*...and 35 more (see evidence/ENT-USR-003.csv)*'
    }
    It 'links the evidence file from the HTML report' {
        $script:Html | Should -BeLike '*<a href="evidence/ENT-USR-003.csv">*'
    }
    It 'adds no evidence folder and no links without the switch' {
        Test-Path (Join-Path $script:Without 'evidence') | Should -BeFalse
        (Get-Content -Raw (Join-Path $script:Without 'M365_Security_Gap_Assessment.md')) | Should -Not -BeLike '*evidence/*'
        (Get-Content -Raw (Join-Path $script:Without 'M365_Security_Gap_Assessment.md')) | Should -BeLike '*(see AssessmentFindings.json)*'
    }
    It 'protects the evidence folder and files like the reports (700 / 600) on macOS and Linux' -Skip:$IsWindows {
        [IO.File]::GetUnixFileMode((Join-Path $script:With 'evidence')) | Should -Be ([IO.UnixFileMode]'UserRead,UserWrite,UserExecute')
        [IO.File]::GetUnixFileMode((Join-Path $script:With 'evidence/ENT-USR-003.csv')) | Should -Be ([IO.UnixFileMode]'UserRead,UserWrite')
        [IO.File]::GetUnixFileMode((Join-Path $script:With 'evidence/_index.csv')) | Should -Be ([IO.UnixFileMode]'UserRead,UserWrite')
    }
}

Describe 'Protect-ExportPath' {
    It 'tightens nested folders and files even when they start out world-readable (700 / 600)' -Skip:$IsWindows {
        # Start from deliberately permissive modes so the result does not depend on the machine's default umask.
        $root = Join-Path $TestDrive 'perm'
        $sub = Join-Path $root 'evidence'
        $null = New-Item -ItemType Directory -Path $sub -Force
        $top = Join-Path $root 'report.md'
        $deep = Join-Path $sub 'ENT-X.csv'
        Set-Content -Path $top, $deep -Value 'x'
        foreach ($d in $root, $sub) { [IO.File]::SetUnixFileMode($d, [IO.UnixFileMode]'UserRead,UserWrite,UserExecute,GroupRead,GroupExecute,OtherRead,OtherExecute') }
        foreach ($f in $top, $deep) { [IO.File]::SetUnixFileMode($f, [IO.UnixFileMode]'UserRead,UserWrite,GroupRead,OtherRead') }

        InModuleScope M365GapAssessment -Parameters @{ R = $root } { Protect-ExportPath -Path $R }

        [IO.File]::GetUnixFileMode($root) | Should -Be ([IO.UnixFileMode]'UserRead,UserWrite,UserExecute')
        [IO.File]::GetUnixFileMode($sub)  | Should -Be ([IO.UnixFileMode]'UserRead,UserWrite,UserExecute')
        [IO.File]::GetUnixFileMode($top)  | Should -Be ([IO.UnixFileMode]'UserRead,UserWrite')
        [IO.File]::GetUnixFileMode($deep) | Should -Be ([IO.UnixFileMode]'UserRead,UserWrite')
    }
}

Describe 'Convert-M365Report with evidence' {
    BeforeAll {
        $script:Dir = Join-Path $TestDrive 'orig'
        $null = Export-M365GapReport -Assessment (New-EvidenceAssessment) -ExportPath $script:Dir -Format JSON -IncludeEvidence
        $script:Json = Join-Path $script:Dir 'AssessmentFindings.json'
    }
    It 'keeps the evidence links when re-rendering into the same folder' {
        $out = @(Convert-M365Report -Path $script:Json -Format Markdown)
        Get-Content -Raw $out[0] | Should -Match ([regex]::Escape('[evidence/ENT-USR-003.csv](evidence/ENT-USR-003.csv)'))
    }
    It 'omits the links when re-rendering somewhere the evidence files are not' {
        $out = @(Convert-M365Report -Path $script:Json -Format Markdown -OutputPath (Join-Path $TestDrive 'elsewhere'))
        $md = Get-Content -Raw $out[0]
        $md | Should -Not -BeLike '*evidence/ENT-USR-003.csv*'
        $md | Should -BeLike '*(see AssessmentFindings.json)*'
    }
    It 'honours -HideTenantId and still links evidence' {
        $out = @(Convert-M365Report -Path $script:Json -Format HTML -HideTenantId)
        $html = Get-Content -Raw $out[0]
        $html | Should -Not -BeLike "*$script:Guid*"
        $html | Should -BeLike '*evidence/ENT-USR-003.csv*'
    }
}

Describe 'Invoke-M365SecurityReview parameter' {
    It 'exposes -IncludeEvidence as a switch' {
        (Get-Command Invoke-M365SecurityReview).Parameters['IncludeEvidence'].ParameterType.Name | Should -Be 'SwitchParameter'
    }
}
