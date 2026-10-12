#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Private/Get-AdminAccountHygieneGaps.ps1 (ENT-USR-007 hybrid administrators, ENT-USR-008 licensed administrators) with fake Graph: no tenant.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeGraph.ps1')
    Enable-FakeGraph

    # One role assignment as Graph returns it (active instance or eligible schedule).
    function script:Assign {
        param([string]$User, [string]$Role = 'Global Administrator', [string]$Type = 'Assigned', [string]$Kind = 'user')
        @{ principalId = $User; assignmentType = $Type; roleDefinition = @{ displayName = $Role }
            principal = @{ '@odata.type' = "#microsoft.graph.$Kind"; id = $User; displayName = $User } }
    }
    function script:User { param([string]$Id, $Synced) @{ id = $Id; userPrincipalName = "$Id@contoso.com"; displayName = $Id; onPremisesSyncEnabled = $Synced } }
    function script:Plan { param([string]$Name, [string]$Status = 'Success') @{ servicePlanName = $Name; provisioningStatus = $Status } }
    function script:Lic { param([string]$Sku, [object[]]$Plans) @{ skuPartNumber = $Sku; servicePlans = @($Plans) } }

    function script:Invoke-Hygiene {
        param([object[]]$Active = @(), [object[]]$Eligible = @(), [hashtable]$Users = @{}, [hashtable]$Licenses = @{}, [switch]$RolesUnreadable)
        $table = [ordered]@{}
        foreach ($id in $Licenses.Keys) { $table["users/$id/licenseDetails"] = (J (@{ value = @($Licenses[$id]) } | ConvertTo-Json -Depth 8)) }
        foreach ($id in $Users.Keys) { $table["users/$id`?"] = (J (ConvertTo-Json $Users[$id] -Depth 4)) }
        $table['roleAssignmentScheduleInstances'] = $(if ($RolesUnreadable) { { throw 'forbidden' } } else { J (@{ value = @($Active) } | ConvertTo-Json -Depth 8) })
        $table['roleEligibilitySchedules'] = (J (@{ value = @($Eligible) } | ConvertTo-Json -Depth 8))
        Invoke-WithFixture -Fixture (ConvertTo-Fixture $table) -Command 'Get-AdminAccountHygieneGaps'
    }
    $script:Cloud = @{ 'a1' = (User 'a1' $null) }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'Test-AdministratorRoleName' {
    It '<Name> -> <Expected>' -ForEach @(
        @{ Name = 'Global Administrator'; Expected = $true }
        @{ Name = 'Exchange Administrator'; Expected = $true }
        @{ Name = 'Privileged Role Administrator'; Expected = $true }
        @{ Name = 'Global Reader'; Expected = $true }
        @{ Name = 'Security Reader'; Expected = $false }
        @{ Name = 'Directory Writers'; Expected = $false }
    ) { InModuleScope M365GapAssessment -Parameters @{ N = $Name } { Test-AdministratorRoleName $N } | Should -Be $Expected }
}

Describe 'ENT-USR-007 hybrid administrator accounts' {
    It 'passes when every administrator is cloud-only' {
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @() }
        $r['ENT-USR-007'].Status | Should -Be 'Pass'
    }
    It 'is a gap for a synced administrator and names the account and role' {
        $r = Invoke-Hygiene -Active @(Assign 'a1' 'Exchange Administrator') -Users @{ a1 = (User 'a1' $true) }
        $r['ENT-USR-007'].Status | Should -Be 'Gap'
        $r['ENT-USR-007'].AffectedObjects | Should -BeLike 'a1@contoso.com - Exchange Administrator'
    }
    It 'also catches a synced account that is only eligible' {
        $r = Invoke-Hygiene -Eligible @(Assign 'a1' 'Global Administrator' 'Eligible') -Users @{ a1 = (User 'a1' $true) }
        $r['ENT-USR-007'].Status | Should -Be 'Gap'
    }
    It 'ignores a synced user who holds no administrator role' {
        $r = Invoke-Hygiene -Active @(Assign 'a1' 'Directory Readers') -Users @{ a1 = (User 'a1' $true) }
        $r['ENT-USR-007'].Status | Should -Be 'Pass'
    }
    It 'counts Global Reader as administrative, as the benchmark does' {
        $r = Invoke-Hygiene -Active @(Assign 'a1' 'Global Reader') -Users @{ a1 = (User 'a1' $true) }
        $r['ENT-USR-007'].Status | Should -Be 'Gap'
    }
    It 'passes with no administrators at all and says so' {
        $r = Invoke-Hygiene
        $r['ENT-USR-007'].Status | Should -Be 'Pass'
        $r['ENT-USR-007'].Detail | Should -BeLike '0 user(s)*'
    }
    It 'notes role-assigned groups that were not expanded' {
        $r = Invoke-Hygiene -Active @(Assign 'grp1' 'Global Administrator' 'Assigned' 'group')
        $r['ENT-USR-007'].Detail | Should -BeLike '*1 role-assigned group(s) were not expanded: grp1*'
    }
    It 'reports each synced account once per role' {
        $r = Invoke-Hygiene -Active @(Assign 'a1' 'Global Administrator'; Assign 'a1' 'User Administrator') -Users @{ a1 = (User 'a1' $true) }
        @($r['ENT-USR-007'].AffectedObjects).Count | Should -Be 2
    }
}

Describe 'ENT-USR-008 administrator accounts with applications' {
    It 'is a gap for a permanent admin with an Exchange and Teams licence, naming the plans' {
        $lic = Lic 'ENTERPRISEPACK' @((Plan 'EXCHANGE_S_ENTERPRISE'), (Plan 'TEAMS1'), (Plan 'AAD_PREMIUM'))
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @($lic) }
        $r['ENT-USR-008'].Status | Should -Be 'Gap'
        $r['ENT-USR-008'].AffectedObjects | Should -BeLike '*ENTERPRISEPACK*EXCHANGE_S_ENTERPRISE*TEAMS1*'
        $r['ENT-USR-008'].AffectedObjects | Should -Not -BeLike '*AAD_PREMIUM*'
    }
    It 'passes for an Entra ID P2 licence only' {
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @(Lic 'AAD_PREMIUM_P2' @((Plan 'AAD_PREMIUM_P2'), (Plan 'MFA_PREMIUM'))) }
        $r['ENT-USR-008'].Status | Should -Be 'Pass'
    }
    It 'passes when the application plans on a full licence are switched off' {
        $lic = Lic 'ENTERPRISEPACK' @((Plan 'EXCHANGE_S_ENTERPRISE' 'Disabled'), (Plan 'TEAMS1' 'Disabled'), (Plan 'AAD_PREMIUM'))
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @($lic) }
        $r['ENT-USR-008'].Status | Should -Be 'Pass'
    }
    It 'does not treat the free Power Automate licence as an application licence (real plan names from a tenant)' {
        $free = Lic 'FLOW_FREE' @((Plan 'DYN365_CDS_VIRAL'), (Plan 'EXCHANGE_S_FOUNDATION'), (Plan 'FLOW_P2_VIRAL'))
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @($free) }
        $r['ENT-USR-008'].Status | Should -Be 'Pass'
    }
    It 'still sees a real mailbox plan next to the Exchange foundation plan' {
        $biz = Lic 'O365_BUSINESS_ESSENTIALS' @((Plan 'EXCHANGE_S_FOUNDATION'), (Plan 'EXCHANGE_S_STANDARD'), (Plan 'SHAREPOINTSTANDARD'), (Plan 'TEAMS1'))
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @($biz) }
        $r['ENT-USR-008'].Status | Should -Be 'Gap'
        $r['ENT-USR-008'].AffectedObjects | Should -BeLike '*EXCHANGE_S_STANDARD*SHAREPOINTSTANDARD*TEAMS1*'
        $r['ENT-USR-008'].AffectedObjects | Should -Not -BeLike '*EXCHANGE_S_FOUNDATION*'
    }
    It 'recognises the Forms plan names that real licences use' {
        $forms = Lic 'X' @((Plan 'FORMS_PLAN_E5'), (Plan 'AAD_PREMIUM'))
        (Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @($forms) })['ENT-USR-008'].Status | Should -Be 'Gap'
    }
    It 'matches the plans of a Microsoft 365 E7 licence (real plan names from a tenant)' {
        $e7 = Lic 'MICROSOFT_365_E7_NO_TEAMS' @((Plan 'EXCHANGE_S_ENTERPRISE'), (Plan 'SHAREPOINTENTERPRISE'), (Plan 'OFFICESUBSCRIPTION'), (Plan 'MCOSTANDARD'), (Plan 'YAMMER_ENTERPRISE'), (Plan 'AAD_PREMIUM_P2'), (Plan 'INTUNE_A'), (Plan 'WINDEFATP'))
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @($e7) }
        $r['ENT-USR-008'].AffectedObjects | Should -BeLike '*EXCHANGE_S_ENTERPRISE*MCOSTANDARD*OFFICESUBSCRIPTION*SHAREPOINTENTERPRISE*YAMMER_ENTERPRISE'
        $r['ENT-USR-008'].AffectedObjects | Should -Not -BeLike '*AAD_PREMIUM*'
        $r['ENT-USR-008'].AffectedObjects | Should -Not -BeLike '*INTUNE*'
    }
    It 'passes for an admin with no licence at all' {
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @() }
        $r['ENT-USR-008'].Status | Should -Be 'Pass'
    }
    It 'exempts accounts that only activate the role through PIM' {
        $lic = Lic 'ENTERPRISEPACK' @((Plan 'EXCHANGE_S_ENTERPRISE'))
        $r = Invoke-Hygiene -Active @(Assign 'a1' 'Global Administrator' 'Activated') -Eligible @(Assign 'a1' 'Global Administrator' 'Eligible') -Users $script:Cloud -Licenses @{ a1 = @($lic) }
        $r['ENT-USR-008'].Status | Should -Be 'Pass'
        $r['ENT-USR-008'].Detail | Should -BeLike '0 account(s) have a permanent*'
    }
    It 'is a gap if any one of several admins holds an application licence' {
        $full = Lic 'SPE_E5' @((Plan 'EXCHANGE_S_ENTERPRISE'))
        $none = Lic 'AAD_PREMIUM_P2' @((Plan 'AAD_PREMIUM_P2'))
        $r = Invoke-Hygiene -Active @(Assign 'a1'; Assign 'b2' 'User Administrator') -Users @{ a1 = (User 'a1' $null); b2 = (User 'b2' $null) } -Licenses @{ a1 = @($none); b2 = @($full) }
        $r['ENT-USR-008'].Status | Should -Be 'Gap'
        @($r['ENT-USR-008'].AffectedObjects) | Should -Be @('b2@contoso.com - SPE_E5: EXCHANGE_S_ENTERPRISE')
    }
}

Describe 'failures stay contained' {
    It 'unreadable role assignments make both checks NotAssessed with the reason' {
        $r = Invoke-Hygiene -RolesUnreadable
        $r['ENT-USR-007'].Status | Should -Be 'NotAssessed'
        $r['ENT-USR-008'].Status | Should -Be 'NotAssessed'
        $r['ENT-USR-007'].Detail | Should -BeLike '*forbidden*'
    }
    It 'a failed licence lookup makes only ENT-USR-008 NotAssessed' {
        # No licenseDetails fixture for a1, so that call throws; the hybrid-account result must survive.
        $r = Invoke-Hygiene -Active @(Assign 'a1') -Users @{ a1 = (User 'a1' $true) }
        $r['ENT-USR-007'].Status | Should -Be 'Gap'
        $r['ENT-USR-008'].Status | Should -Be 'NotAssessed'
        $r['ENT-USR-008'].Detail | Should -BeLike '*licenseDetails*'
    }
    It 'reports each finding exactly once' {
        (Invoke-Hygiene -Active @(Assign 'a1') -Users $script:Cloud -Licenses @{ a1 = @() }).Keys.Count | Should -Be 2
    }
}
