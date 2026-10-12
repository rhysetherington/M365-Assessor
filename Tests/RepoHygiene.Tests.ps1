#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# What a stranger meets first: the licence, the READMEs, the built-in help, the helper script, the prerequisite error and the files that
# must never be committed. These tests exist because each of them was once wrong or missing, and none of them is covered by a check test.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    $script:Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    $script:ModuleDir = Split-Path -Parent (Get-ModuleUnderTestPath)
    $script:Mapping = Get-Content -Raw (Join-Path $script:ModuleDir 'Data/ControlMapping.json') | ConvertFrom-Json
    $script:Domain = (Get-Command Invoke-M365SecurityReview).Parameters['Domain']
    $script:AllDomains = @($script:Domain.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })
    $script:Commands = @(Get-Command -Module M365GapAssessment)
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Licence' {
    It 'has a LICENSE file that is the MIT licence with a named copyright holder' {
        $text = Get-Content -Raw (Join-Path $script:Repo 'LICENSE')
        $text | Should -Match '^MIT License'
        $text | Should -Match 'Copyright \(c\) \d{4} \S+'
        $text | Should -BeLike '*Permission is hereby granted, free of charge*'
    }
    It 'is declared in the module manifest, with the project and licence addresses' {
        $psd = Import-PowerShellDataFile (Join-Path $script:ModuleDir 'M365GapAssessment.psd1')
        $psd.Copyright | Should -BeLike '*MIT*'
        $psd.PrivateData.PSData.ProjectUri | Should -Match '^https://github\.com/'
        $psd.PrivateData.PSData.LicenseUri | Should -Match '^https://github\.com/.+/LICENSE$'
    }
}

Describe 'Root README' {
    BeforeAll { $script:RootReadme = Get-Content -Raw (Join-Path $script:Repo 'README.md') }

    It 'exists, so the repository landing page explains the project' {
        $script:RootReadme.Length | Should -BeGreaterThan 500
    }
    It 'states the number of checks, and it matches the control mapping' {
        $m = [regex]::Match($script:RootReadme, '\*\*(\d+) checks\*\*')
        $m.Success | Should -BeTrue -Because 'the README should say "**N checks**"'
        [int]$m.Groups[1].Value | Should -Be @($script:Mapping.controls).Count
    }
    It 'links only to files and folders that exist' {
        $links = [regex]::Matches($script:RootReadme, '\]\((?!https?:|#|mailto:)([^)\s#]+)') | ForEach-Object { $_.Groups[1].Value }
        $links | Should -Not -BeNullOrEmpty
        foreach ($l in $links) { Test-Path (Join-Path $script:Repo $l) | Should -BeTrue -Because "README links to $l" }
    }
    It 'tells a newcomer how to run it, what it needs and where the report goes' {
        $script:RootReadme | Should -BeLike '*Install-Module Microsoft.Graph.Authentication*'
        $script:RootReadme | Should -BeLike '*Invoke-M365SecurityReview*'
        $script:RootReadme | Should -BeLike '*Global Reader*'
        $script:RootReadme | Should -BeLike '*M365Assessment/*'
    }
    It 'points at the licence' { $script:RootReadme | Should -BeLike '*](LICENSE)*' }
}

Describe 'Module README' {
    BeforeAll { $script:ModuleReadme = Get-Content -Raw (Join-Path $script:ModuleDir 'README.md') }

    It 'has no leftover claim that folders are named after the tenant ID' {
        $script:ModuleReadme | Should -Not -BeLike '*<tenantId>_*'
    }
    It 'documents every domain the command accepts' {
        # Backticks are the wildcard escape in -like, so these checks use .Contains().
        $tick = [string][char]96
        foreach ($d in $script:AllDomains) { $script:ModuleReadme.Contains($tick + $d + $tick) | Should -BeTrue -Because "domain $d should be in the README" }
    }
    It 'lists the default domains exactly as the command defines them' {
        $tick = [string][char]96
        $param = $script:Commands.Where({ $_.Name -eq 'Invoke-M365SecurityReview' })[0].ScriptBlock.Ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Domain' }
        $defaults = @($param.DefaultValue.SafeGetValue())
        $defaults.Count | Should -BeGreaterThan 0
        $defaultText = ($defaults | ForEach-Object { $tick + $_ + $tick }) -join ', '
        $script:ModuleReadme.Contains("Domains run by default: $defaultText") | Should -BeTrue -Because "README should say: Domains run by default: $defaultText"
        $optIn = @($script:AllDomains | Where-Object { $_ -notin $defaults })
        $optText = ($optIn | ForEach-Object { $tick + $_ + $tick }) -join ', '
        $script:ModuleReadme.Contains("Opt-in (add with") | Should -BeTrue
        $script:ModuleReadme.Contains($optText) | Should -BeTrue -Because "README should list the opt-in domains: $optText"
    }
    It 'has a section for someone checking their own tenant' {
        $script:ModuleReadme | Should -BeLike '*## Check your own tenant*'
    }
}

Describe 'Built-in help' {
    It '<_> has a synopsis, a description of every parameter and an example' -ForEach @(
        'Invoke-M365SecurityReview', 'Connect-M365Assessment', 'Export-M365GapReport', 'Compare-M365Assessment', 'Convert-M365Report'
    ) {
        $h = Get-Help $_ -Full
        $h.Synopsis.Trim() | Should -Not -BeNullOrEmpty
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        $bad = @($h.parameters.parameter | Where-Object { $_.Name -notin $common -and -not ($_.description | Out-String).Trim() } | ForEach-Object Name)
        $bad | Should -BeNullOrEmpty -Because "parameters without help: $($bad -join ', ')"
        @($h.examples.example).Count | Should -BeGreaterThan 0
    }
    It 'every command exported by the module is covered above' {
        @($script:Commands.Name | Sort-Object) | Should -Be @('Compare-M365Assessment', 'Connect-M365Assessment', 'Convert-M365Report', 'Export-M365GapReport', 'Invoke-M365SecurityReview')
    }
    It 'describes the assessment as read-only and mentions every opt-in domain' {
        $d = (Get-Help Invoke-M365SecurityReview -Full | Out-String)
        $d | Should -BeLike '*read-only*'
        foreach ($x in 'ExchangeOnline', 'DefenderO365', 'Purview', 'Teams') { $d | Should -BeLike "*$x*" }
    }
}

Describe 'Files that must not be committed' {
    BeforeAll { $script:Ignore = @(Get-Content (Join-Path $script:Repo '.gitignore') | ForEach-Object { $_.Trim() }) }

    It 'ignores the default export folder of Invoke-M365SecurityReview, where reports with tenant data are written' {
        $default = [regex]::Match((Get-Content -Raw (Join-Path $script:ModuleDir 'Public/Invoke-M365SecurityReview.ps1')), "ExportPath = \(Join-Path \(Get-Location\) '([^']+)'\)").Groups[1].Value
        $default | Should -Not -BeNullOrEmpty
        $script:Ignore | Should -Contain "$default/"
    }
    It 'ignores the folder run-assessment.ps1 writes to' {
        (Get-Content -Raw (Join-Path $script:Repo 'run-assessment.ps1')) | Should -BeLike '*"$PSScriptRoot/Assessments"*'
        $script:Ignore | Should -Contain 'Assessments/'
    }
}

Describe 'No real tenant names in the repository' {
    It 'every *.onmicrosoft.com name in the docs and code is a recognisable example' {
        $allowed = '', 'mail', 'contoso', 'fabrikam', 'tenant', 'yourtenant', 'tenantA', 'tenantB', 'client1', 'client2', 'client3'
        $files = @('README.md', 'run-assessment.ps1', 'LICENSE') | ForEach-Object { Join-Path $script:Repo $_ }
        $files += Get-ChildItem (Join-Path $script:Repo 'Docs') -Filter '*.md' | ForEach-Object FullName
        $files += Get-ChildItem $script:ModuleDir -Recurse -Include '*.ps1', '*.psm1', '*.psd1', '*.md', '*.json' | ForEach-Object FullName
        $unexpected = foreach ($f in $files) {
            foreach ($m in [regex]::Matches((Get-Content -Raw $f), '([A-Za-z0-9_-]*)\.onmicrosoft\.com')) {
                if ($m.Groups[1].Value -notin $allowed) { "$([IO.Path]::GetFileName($f)): $($m.Value)" }
            }
        }
        $unexpected | Should -BeNullOrEmpty -Because "use contoso.onmicrosoft.com in examples. Found: $($unexpected -join '; ')"
    }
}

Describe 'run-assessment.ps1' {
    BeforeAll { $script:RunScript = Join-Path $script:Repo 'run-assessment.ps1' }

    It 'has no hard-coded domain list that can fall behind the command' {
        (Get-Content -Raw $script:RunScript) | Should -Not -Match '-Domain\s+[A-Za-z]+,'
    }
    It 'runs every domain the command accepts, including the opt-in ones' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:RunScript, [ref]$null, [ref]$null)
        $assign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$allDomains' }, $true)
        $assign | Should -Not -BeNullOrEmpty
        $domains = @(& ([scriptblock]::Create($assign.Right.Extent.Text)))
        @($domains | Sort-Object) | Should -Be @($script:AllDomains | Sort-Object)
        $domains | Should -Contain 'DefenderO365'
        $domains | Should -Contain 'Purview'
    }
}

Describe 'Loading the Graph module' {
    It 'is loaded once, in the global session, after repeated forced imports (as RequiredModules did)' {
        Import-Module (Get-ModuleUnderTestPath) -Force
        Import-Module (Get-ModuleUnderTestPath) -Force
        $loaded = @(Get-Module -Name Microsoft.Graph.Authentication)
        $loaded.Count | Should -Be 1
        # Global scope means a command from it is visible outside the module as well.
        $null = Get-Command Get-MgContext -ErrorAction Stop
    }
    It 'a fresh session can import the module twice with -Force and still reach the Graph commands' -Skip:(-not (Get-Process -Id $PID).Path) {
        $pwsh = (Get-Process -Id $PID).Path
        $psd = Get-ModuleUnderTestPath
        $out = & $pwsh -NoProfile -NonInteractive -Command "Import-Module '$psd' -Force; Import-Module '$psd' -Force; & (Get-Module M365GapAssessment) { `$null = Get-MgContext; 'GRAPH-OK' }" 2>&1 | Out-String
        $out | Should -BeLike '*GRAPH-OK*'
    }
}

Describe 'Missing prerequisite' {
    It 'importing without the Graph module says how to install it' -Skip:(-not (Get-Process -Id $PID).Path) {
        $pwsh = (Get-Process -Id $PID).Path
        $empty = Join-Path $TestDrive 'no-modules'
        New-Item -ItemType Directory -Path $empty | Out-Null
        $psd = Get-ModuleUnderTestPath
        $out = & $pwsh -NoProfile -NonInteractive -Command "`$env:PSModulePath = '$empty'; try { Import-Module '$psd' -Force -ErrorAction Stop; 'IMPORTED' } catch { `$_.Exception.Message }" 2>&1 | Out-String
        $out | Should -Not -BeLike '*IMPORTED*'
        $out | Should -BeLike '*Install-Module Microsoft.Graph.Authentication*'
        $out | Should -BeLike '*2.0.0*'
    }
}
