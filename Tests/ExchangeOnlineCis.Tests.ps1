#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# EXO-009..EXO-014 (CIS 6.5.5, 6.5.2, 6.3.2, 6.3.1, 6.1.3, 6.1.2) in Get-ExchangeOnlineGaps with a fake session and fake cmdlets: no tenant.

BeforeAll {
    . (Join-Path $PSScriptRoot 'Support/TestSupport.ps1')
    Import-Module (Get-ModuleUnderTestPath) -Force -ErrorAction Stop
    . (Join-Path $PSScriptRoot 'Support/FakeCmdlets.ps1')
    InModuleScope M365GapAssessment { function script:Start-ExchangeSession { param($TenantId) [pscustomobject]@{ Ready = $true; Error = $null } } }

    function script:J($Json) { $Json | ConvertFrom-Json }

    $script:AdminActions = 'ApplyRecord', 'Copy', 'Create', 'FolderBind', 'HardDelete', 'MailItemsAccessed', 'Move', 'MoveToDeletedItems', 'SendAs', 'SendOnBehalf', 'Send', 'SoftDelete', 'Update', 'UpdateCalendarDelegation', 'UpdateFolderPermissions', 'UpdateInboxRules'
    $script:DelegateActions = 'ApplyRecord', 'Create', 'FolderBind', 'HardDelete', 'Move', 'MailItemsAccessed', 'MoveToDeletedItems', 'SendAs', 'SendOnBehalf', 'SoftDelete', 'Update', 'UpdateFolderPermissions', 'UpdateInboxRules'
    $script:OwnerActions = 'ApplyRecord', 'Create', 'HardDelete', 'MailboxLogin', 'Move', 'MailItemsAccessed', 'MoveToDeletedItems', 'Send', 'SoftDelete', 'Update', 'UpdateCalendarDelegation', 'UpdateFolderPermissions', 'UpdateInboxRules'

    function script:New-Mailbox {
        param([string]$Upn = 'alice@contoso.com', [string]$Type = 'UserMailbox', [bool]$Enabled = $true, $Admin = $script:AdminActions, $Delegate = $script:DelegateActions, $Owner = $script:OwnerActions)
        [pscustomobject]@{ UserPrincipalName = $Upn; RecipientTypeDetails = $Type; AuditEnabled = $Enabled; AuditAdmin = @($Admin); AuditDelegate = @($Delegate); AuditOwner = @($Owner) }
    }

    function script:Get-Healthy {
        @{
            'Get-OrganizationConfig'            = (J '{"RejectDirectSend":true,"MailTipsAllTipsEnabled":true,"MailTipsExternalRecipientsTipsEnabled":true,"MailTipsGroupMetricsEnabled":true}')
            'Get-OwaMailboxPolicy'              = (J '[{"Name":"OwaMailboxPolicy-Default","IsDefault":true,"PersonalAccountsEnabled":false,"PersonalAccountCalendarsEnabled":false,"AdditionalStorageProvidersAvailable":false}]')
            'Get-RoleAssignmentPolicy'          = (J '[{"Name":"Default Role Assignment Policy","IsDefault":true,"AssignedRoles":["MyBaseOptions","MyContactInformation"]}]')
            'Get-MailboxAuditBypassAssociation' = (J '[{"Name":"alice","AuditBypassEnabled":false}]')
            'Get-EXOMailbox'                    = @(New-Mailbox)
        }
    }

    function script:Invoke-Exo {
        param([hashtable]$Set = @{}, [string[]]$Remove = @())
        $data = Get-Healthy
        foreach ($k in $Set.Keys) { $data[$k] = if ($Set[$k] -is [string]) { J $Set[$k] } else { $Set[$k] } }
        foreach ($k in $Remove) { $data.Remove($k) }
        Invoke-WithCmdlets -Data $data -Command 'Get-ExchangeOnlineGaps'
    }
}

AfterAll { Remove-Module M365GapAssessment -Force -ErrorAction SilentlyContinue }

Describe 'EXO-009 Direct Send (CIS 6.5.5)' {
    It 'passes when Direct Send is rejected' { (Invoke-Exo)['EXO-009'].Status | Should -Be 'Pass' }
    It 'is a gap when it is not' {
        (Invoke-Exo -Set @{ 'Get-OrganizationConfig' = '{"RejectDirectSend":false}' })['EXO-009'].Status | Should -Be 'Gap'
    }
    It 'is NotAssessed, not a pass, when the setting is not returned' {
        $f = (Invoke-Exo -Set @{ 'Get-OrganizationConfig' = '{"AuditDisabled":false}' })['EXO-009']
        $f.Status | Should -Be 'NotAssessed'
        $f.Detail | Should -BeLike '*RejectDirectSend*'
    }
}

Describe 'EXO-010 MailTips (CIS 6.5.2)' {
    It 'passes when all three tips are on' { (Invoke-Exo)['EXO-010'].Status | Should -Be 'Pass' }
    It 'is a gap when external recipient tips are off, and names the setting' {
        $f = (Invoke-Exo -Set @{ 'Get-OrganizationConfig' = '{"RejectDirectSend":true,"MailTipsAllTipsEnabled":true,"MailTipsExternalRecipientsTipsEnabled":false,"MailTipsGroupMetricsEnabled":true}' })['EXO-010']
        $f.Status | Should -Be 'Gap'
        @($f.AffectedObjects) | Should -Be @('MailTipsExternalRecipientsTipsEnabled = False')
    }
    It 'is NotAssessed when a tip setting is not returned' {
        (Invoke-Exo -Set @{ 'Get-OrganizationConfig' = '{"RejectDirectSend":true,"MailTipsAllTipsEnabled":true}' })['EXO-010'].Status | Should -Be 'NotAssessed'
    }
}

Describe 'EXO-011 personal accounts in Outlook on the web (CIS 6.3.2)' {
    It 'passes when the default policy blocks personal accounts and calendars' { (Invoke-Exo)['EXO-011'].Status | Should -Be 'Pass' }
    It 'is a gap when personal accounts are allowed' {
        $f = (Invoke-Exo -Set @{ 'Get-OwaMailboxPolicy' = '[{"Name":"OwaMailboxPolicy-Default","IsDefault":true,"PersonalAccountsEnabled":true,"PersonalAccountCalendarsEnabled":false}]' })['EXO-011']
        $f.Status | Should -Be 'Gap'
        $f.AffectedObjects | Should -BeLike '*PersonalAccountsEnabled = True'
    }
    It 'is a gap when personal calendars are allowed' {
        (Invoke-Exo -Set @{ 'Get-OwaMailboxPolicy' = '[{"Name":"D","IsDefault":true,"PersonalAccountsEnabled":false,"PersonalAccountCalendarsEnabled":true}]' })['EXO-011'].Status | Should -Be 'Gap'
    }
    It 'judges the default policy, as the benchmark does, not other policies' {
        $policies = '[{"Name":"D","IsDefault":true,"PersonalAccountsEnabled":false,"PersonalAccountCalendarsEnabled":false},{"Name":"Sales","IsDefault":false,"PersonalAccountsEnabled":true,"PersonalAccountCalendarsEnabled":true}]'
        (Invoke-Exo -Set @{ 'Get-OwaMailboxPolicy' = $policies })['EXO-011'].Status | Should -Be 'Pass'
    }
    It 'is NotAssessed when there is no default policy' {
        (Invoke-Exo -Set @{ 'Get-OwaMailboxPolicy' = '[{"Name":"X","IsDefault":false}]' })['EXO-011'].Status | Should -Be 'NotAssessed'
    }
    It 'is NotAssessed, not a pass, when one setting is off and the other is not returned' {
        $f = (Invoke-Exo -Set @{ 'Get-OwaMailboxPolicy' = '[{"Name":"D","IsDefault":true,"PersonalAccountsEnabled":false}]' })['EXO-011']
        $f.Status | Should -Be 'NotAssessed'
        $f.Detail | Should -BeLike '*PersonalAccountCalendarsEnabled was not returned*'
    }
    It 'is still a gap when one setting is on and the other is not returned (seen in a real tenant)' {
        $f = (Invoke-Exo -Set @{ 'Get-OwaMailboxPolicy' = '[{"Name":"D","IsDefault":true,"PersonalAccountsEnabled":null,"PersonalAccountCalendarsEnabled":true}]' })['EXO-011']
        $f.Status | Should -Be 'Gap'
        @($f.AffectedObjects) | Should -Be @('D: PersonalAccountCalendarsEnabled = True')
        $f.Detail | Should -BeLike '*PersonalAccountsEnabled = not returned*PersonalAccountsEnabled was not returned*'
    }
    It 'is NotAssessed when neither setting is returned' {
        (Invoke-Exo -Set @{ 'Get-OwaMailboxPolicy' = '[{"Name":"D","IsDefault":true}]' })['EXO-011'].Status | Should -Be 'NotAssessed'
    }
}

Describe 'EXO-012 add-in installation (CIS 6.3.1)' {
    It 'passes when the default policy assigns none of the add-in roles' { (Invoke-Exo)['EXO-012'].Status | Should -Be 'Pass' }
    It 'is a gap for <Role>' -ForEach @(@{ Role = 'My Custom Apps' }, @{ Role = 'My Marketplace Apps' }, @{ Role = 'My ReadWriteMailbox Apps' }) {
        $json = '[{"Name":"Default Role Assignment Policy","IsDefault":true,"AssignedRoles":["MyBaseOptions","' + $Role + '"]}]'
        $f = (Invoke-Exo -Set @{ 'Get-RoleAssignmentPolicy' = $json })['EXO-012']
        $f.Status | Should -Be 'Gap'
        $f.AffectedObjects | Should -BeLike "*$Role"
    }
    It 'ignores add-in roles on a policy that is not the default' {
        $json = '[{"Name":"D","IsDefault":true,"AssignedRoles":["MyBaseOptions"]},{"Name":"Devs","IsDefault":false,"AssignedRoles":["My Custom Apps"]}]'
        (Invoke-Exo -Set @{ 'Get-RoleAssignmentPolicy' = $json })['EXO-012'].Status | Should -Be 'Pass'
    }
    It 'is NotAssessed when no default policy is returned' {
        (Invoke-Exo -Set @{ 'Get-RoleAssignmentPolicy' = '[]' })['EXO-012'].Status | Should -Be 'NotAssessed'
    }
}

Describe 'EXO-013 audit bypass (CIS 6.1.3)' {
    It 'passes when nothing is on bypass' { (Invoke-Exo)['EXO-013'].Status | Should -Be 'Pass' }
    It 'is a gap and names the account on bypass' {
        $f = (Invoke-Exo -Set @{ 'Get-MailboxAuditBypassAssociation' = '[{"Name":"alice","AuditBypassEnabled":false},{"Name":"svc-backup","AuditBypassEnabled":true}]' })['EXO-013']
        $f.Status | Should -Be 'Gap'
        @($f.AffectedObjects) | Should -Be @('svc-backup')
    }
    It 'passes with an empty list' { (Invoke-Exo -Set @{ 'Get-MailboxAuditBypassAssociation' = '[]' })['EXO-013'].Status | Should -Be 'Pass' }
}

Describe 'EXO-014 mailbox audit actions (CIS 6.1.2)' {
    It 'passes when every expected action is audited' { (Invoke-Exo)['EXO-014'].Status | Should -Be 'Pass' }
    It 'is a gap when an owner action is missing, naming mailbox, logon type and action' {
        $owner = @($script:OwnerActions | Where-Object { $_ -ne 'MailItemsAccessed' })
        $f = (Invoke-Exo -Set @{ 'Get-EXOMailbox' = @(New-Mailbox -Owner $owner) })['EXO-014']
        $f.Status | Should -Be 'Gap'
        $f.AffectedObjects | Should -BeLike 'alice@contoso.com*AuditOwner missing MailItemsAccessed*'
    }
    It 'is a gap when a delegate action is missing' {
        $delegate = @($script:DelegateActions | Where-Object { $_ -ne 'SendAs' })
        (Invoke-Exo -Set @{ 'Get-EXOMailbox' = @(New-Mailbox -Delegate $delegate) })['EXO-014'].Status | Should -Be 'Gap'
    }
    It 'is a gap when an admin action is missing' {
        $admin = @($script:AdminActions | Where-Object { $_ -ne 'Copy' })
        (Invoke-Exo -Set @{ 'Get-EXOMailbox' = @(New-Mailbox -Admin $admin) })['EXO-014'].Status | Should -Be 'Gap'
    }
    It 'is a gap when auditing is switched off for the mailbox' {
        $f = (Invoke-Exo -Set @{ 'Get-EXOMailbox' = @(New-Mailbox -Enabled $false) })['EXO-014']
        $f.Status | Should -Be 'Gap'
        $f.AffectedObjects | Should -BeLike '*auditing is off*'
    }
    It 'accepts extra audited actions' {
        (Invoke-Exo -Set @{ 'Get-EXOMailbox' = @(New-Mailbox -Owner (@($script:OwnerActions) + 'SearchQueryInitiated')) })['EXO-014'].Status | Should -Be 'Pass'
    }
    It 'only judges user mailboxes' {
        $shared = New-Mailbox -Upn 'shared@contoso.com' -Type 'SharedMailbox' -Enabled $false -Admin @() -Delegate @() -Owner @()
        (Invoke-Exo -Set @{ 'Get-EXOMailbox' = @((New-Mailbox), $shared) })['EXO-014'].Status | Should -Be 'Pass'
    }
    It 'is NotAssessed, not a pass, when the audit properties are not returned' {
        $bare = [pscustomobject]@{ UserPrincipalName = 'alice@contoso.com'; RecipientTypeDetails = 'UserMailbox' }
        $f = (Invoke-Exo -Set @{ 'Get-EXOMailbox' = @($bare) })['EXO-014']
        $f.Status | Should -Be 'NotAssessed'
        $f.Detail | Should -BeLike '*AuditAdmin*'
    }
    It 'reports the Microsoft default audit set as a gap, naming what CIS expects beyond it (seen in a real tenant)' {
        $admin = 'Update', 'MoveToDeletedItems', 'SoftDelete', 'HardDelete', 'SendAs', 'SendOnBehalf', 'Create', 'UpdateFolderPermissions', 'UpdateInboxRules', 'UpdateCalendarDelegation', 'ApplyRecord', 'MailItemsAccessed', 'Send'
        $delegate = 'Update', 'MoveToDeletedItems', 'SoftDelete', 'HardDelete', 'SendAs', 'SendOnBehalf', 'Create', 'UpdateFolderPermissions', 'UpdateInboxRules', 'ApplyRecord', 'MailItemsAccessed'
        $owner = 'Update', 'MoveToDeletedItems', 'SoftDelete', 'HardDelete', 'Create', 'UpdateFolderPermissions', 'UpdateInboxRules', 'UpdateCalendarDelegation', 'ApplyRecord', 'MailItemsAccessed', 'Send'
        $f = (Invoke-Exo -Set @{ 'Get-EXOMailbox' = @(New-Mailbox -Admin $admin -Delegate $delegate -Owner $owner) })['EXO-014']
        $f.Status | Should -Be 'Gap'
        $f.AffectedObjects | Should -BeLike '*AuditAdmin missing Copy, FolderBind, Move*AuditDelegate missing FolderBind, Move*AuditOwner missing MailboxLogin, Move*'
    }
    It 'caps a long list and says how many more there are' {
        $many = @(1..105 | ForEach-Object { New-Mailbox -Upn "u$_@contoso.com" -Enabled $false })
        $f = (Invoke-Exo -Set @{ 'Get-EXOMailbox' = $many })['EXO-014']
        $f.Status | Should -Be 'Gap'
        @($f.AffectedObjects).Count | Should -Be 101
        @($f.AffectedObjects)[-1] | Should -Be '... and 5 more'
        $f.Detail | Should -BeLike '105 of 105*'
    }
}

Describe 'failures stay contained' {
    It 'a refused cmdlet makes only its own check NotAssessed' {
        $r = Invoke-Exo -Set @{ 'Get-RoleAssignmentPolicy' = { throw 'access denied' } }
        $r['EXO-012'].Status | Should -Be 'NotAssessed'
        $r['EXO-012'].Detail | Should -BeLike '*access denied*'
        $r['EXO-011'].Status | Should -Be 'Pass'
    }
    It 'a healthy tenant passes all six new checks, each reported once' {
        $r = Invoke-Exo
        foreach ($id in 'EXO-009', 'EXO-010', 'EXO-011', 'EXO-012', 'EXO-013', 'EXO-014') { $r[$id].Status | Should -Be 'Pass' -Because $id }
    }
}
