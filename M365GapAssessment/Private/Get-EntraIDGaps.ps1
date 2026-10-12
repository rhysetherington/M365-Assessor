function Get-EntraIDGaps {
    <#
    .SYNOPSIS
        Entra ID collector: Conditional Access, privileged roles, MFA registration, stale accounts, app credentials/permissions, guest groups.
    #>
    [CmdletBinding()]
    param(
        [int]$StaleDays = 90,
        [int]$SecretWarningDays = 30
    )

    $now = [datetime]::UtcNow
    $globalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    $privilegedRoles = @(
        'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
        'Security Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'User Administrator',
        'Application Administrator', 'Cloud Application Administrator', 'Conditional Access Administrator',
        'Authentication Administrator', 'Intune Administrator', 'Hybrid Identity Administrator'
    )
    $highRiskPermissions = @(
        'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All', 'Mail.ReadWrite',
        'Mail.Send', 'Files.ReadWrite.All', 'Sites.FullControl.All', 'Policy.ReadWrite.ConditionalAccess',
        'PrivilegedAccess.ReadWrite.AzureAD', 'full_access_as_app'
    )

    # --- Conditional Access -------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'Conditional Access policies' -PercentComplete 5
    Invoke-Collector -Name 'Conditional Access' -FindingIds 'ENT-CA-001', 'ENT-CA-002', 'ENT-CA-003', 'ENT-CA-004' -Script {
        $policies   = @(Get-GraphPagedResult -Uri '/v1.0/identity/conditionalAccess/policies')
        $enabled    = @($policies | Where-Object { $_.state -eq 'enabled' })
        $reportOnly = @($policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

        New-Finding -Id 'ENT-CA-001' -Status $(if ($reportOnly.Count) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects @($reportOnly | ForEach-Object { $_.displayName }) `
            -Detail "$($reportOnly.Count) of $($policies.Count) policies are report-only (not enforced)."

        # Heuristic: an enabled all-users policy with no user/group exclusions cannot be exempting break-glass accounts.
        $noExclusions = @($enabled | Where-Object {
                ($_.conditions.users.includeUsers -contains 'All') -and
                -not (Test-HasItems $_.conditions.users.excludeUsers) -and
                -not (Test-HasItems $_.conditions.users.excludeGroups)
            })
        New-Finding -Id 'ENT-CA-002' -Status $(if ($noExclusions.Count) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects @($noExclusions | ForEach-Object { $_.displayName }) `
            -Detail 'Heuristic: enabled policies targeting All users with no excluded users or groups. Verify emergency accounts are excluded.'

        $legacyBlock = @($enabled | Where-Object {
                $c = $_.conditions
                ($c.users.includeUsers -contains 'All') -and ($c.applications.includeApplications -contains 'All') -and
                ($c.clientAppTypes -contains 'exchangeActiveSync') -and ($c.clientAppTypes -contains 'other') -and
                ($_.grantControls.builtInControls -contains 'block')
            })
        # Security Defaults is an alternative to Conditional Access: it also blocks legacy authentication and requires admin MFA.
        $securityDefaults = Get-SecurityDefaultsState
        $sdUnknown = if ($null -eq $securityDefaults) { ' Security Defaults state could not be read, so it was not taken into account.' } else { '' }

        $legacyPass = $legacyBlock.Count -gt 0 -or $securityDefaults -eq $true
        New-Finding -Id 'ENT-CA-003' -Status $(if ($legacyPass) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($legacyBlock.Count) { "Blocked by: $($legacyBlock.displayName -join ', ')" }
                elseif ($securityDefaults -eq $true) { 'Covered by Security Defaults, which blocks legacy authentication. No Conditional Access policy does so.' }
                else { "No enabled policy blocks Exchange ActiveSync + other legacy clients for all users/apps, and Security Defaults is not enabled.$sdUnknown" })

        $adminMfa = @($enabled | Where-Object {
                $c = $_.conditions
                (($c.users.includeUsers -contains 'All') -or ($c.users.includeRoles -contains $globalAdminTemplateId)) -and
                ($c.applications.includeApplications -contains 'All') -and
                (($_.grantControls.builtInControls -contains 'mfa') -or ($null -ne $_.grantControls.authenticationStrength))
            })
        $adminPass = $adminMfa.Count -gt 0 -or $securityDefaults -eq $true
        New-Finding -Id 'ENT-CA-004' -Status $(if ($adminPass) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($adminMfa.Count) { "Enforced by: $($adminMfa.displayName -join ', ')" }
                elseif ($securityDefaults -eq $true) { 'Covered by Security Defaults, which requires MFA for administrators. Consider Conditional Access for phishing-resistant strength and finer control.' }
                else { "No enabled policy requires MFA / authentication strength for Global Administrators across all cloud apps, and Security Defaults is not enabled.$sdUnknown" })
    }

    # --- Privileged roles (PIM) ---------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'Privileged role assignments' -PercentComplete 20
    Invoke-Collector -Name 'Privileged roles' -FindingIds 'ENT-USR-001', 'ENT-USR-005' -Script {
        $instances = @(Get-GraphPagedResult -Uri '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal,roleDefinition')

        $permanent = @($instances | Where-Object {
                $_.assignmentType -eq 'Assigned' -and $null -eq $_.endDateTime -and
                $_.roleDefinition.displayName -in $privilegedRoles
            })
        $labels = @($permanent | ForEach-Object {
                $who = if ($_.principal.userPrincipalName) { $_.principal.userPrincipalName } else { "$($_.principal.displayName) (group/SP)" }
                "$who - $($_.roleDefinition.displayName)"
            })
        New-Finding -Id 'ENT-USR-001' -Status $(if ($labels.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $labels `
            -Detail 'Permanent active assignments to privileged roles. Break-glass accounts are expected here; review the rest.'

        $gaUsers = @($instances | Where-Object { $_.roleDefinition.displayName -eq 'Global Administrator' -and $_.principal.'@odata.type' -eq '#microsoft.graph.user' } |
                ForEach-Object { $_.principal.userPrincipalName } | Sort-Object -Unique)
        New-Finding -Id 'ENT-USR-005' -Status $(if ($gaUsers.Count -gt 5) { 'Gap' } else { 'Pass' }) -AffectedObjects $(if ($gaUsers.Count -gt 5) { $gaUsers } else { @() }) `
            -Detail "$($gaUsers.Count) distinct users hold Global Administrator (active or activated). Threshold: 5."
    }

    # --- Stale eligible PIM assignments --------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'Stale eligible assignments' -PercentComplete 30
    Invoke-Collector -Name 'Stale eligible assignments' -FindingIds 'ENT-USR-006' -Script {
        $cutoff = $now.AddDays(-$StaleDays)
        $eligible = @(Get-GraphPagedResult -Uri '/v1.0/roleManagement/directory/roleEligibilitySchedules?$expand=principal,roleDefinition' |
                Where-Object { $_.roleDefinition.displayName -in $privilegedRoles })

        # Eligibility never expires on its own, so judge it by the holder: disabled, or no sign-in within $StaleDays.
        $userIds = @($eligible | Where-Object { $_.principal.'@odata.type' -eq '#microsoft.graph.user' } | ForEach-Object { $_.principalId } | Sort-Object -Unique)
        $users = @{}
        foreach ($id in $userIds) {
            $users[$id] = Invoke-GraphRequestWithRetry -Uri "/v1.0/users/$id`?`$select=id,userPrincipalName,accountEnabled,createdDateTime,signInActivity"
        }

        $stale = foreach ($e in $eligible) {
            $role = $e.roleDefinition.displayName
            if ($e.principal.'@odata.type' -ne '#microsoft.graph.user') { continue }
            $u = $users[$e.principalId]
            if (-not $u) { continue }
            if ($u.accountEnabled -eq $false) { "$($u.userPrincipalName) - $role (account disabled)"; continue }
            $dates = @($u.signInActivity.lastSignInDateTime, $u.signInActivity.lastNonInteractiveSignInDateTime, $u.signInActivity.lastSuccessfulSignInDateTime |
                    Where-Object { $_ } | ForEach-Object { ([datetime]$_).ToUniversalTime() })
            if ($dates.Count) {
                $last = ($dates | Measure-Object -Maximum).Maximum
                if ($last -lt $cutoff) { "$($u.userPrincipalName) - $role (last sign-in $($last.ToString('yyyy-MM-dd')))" }
            }
            elseif (([datetime]$u.createdDateTime).ToUniversalTime() -lt $cutoff) {
                "$($u.userPrincipalName) - $role (never signed in)"
            }
        }
        New-Finding -Id 'ENT-USR-006' -Status $(if (@($stale).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($stale) `
            -Detail "Eligible privileged role assignments held by users disabled or inactive for more than $StaleDays days ($($eligible.Count) eligible assignments reviewed). Eligible users who never activate are unused standing privilege."
    }

    # --- MFA registration ---------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'MFA registration' -PercentComplete 40
    Invoke-Collector -Name 'MFA registration' -FindingIds 'ENT-USR-003', 'ENT-USR-004' -Script {
        $reg = @(Get-GraphPagedResult -Uri '/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999')

        $noMfa = @($reg | Where-Object { $_.isMfaRegistered -eq $false -and $_.userType -eq 'member' })
        New-Finding -Id 'ENT-USR-003' -Status $(if ($noMfa.Count) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects @($noMfa | ForEach-Object { $_.userPrincipalName }) `
            -Detail "$($noMfa.Count) of $($reg.Count) users have no MFA method registered (report includes disabled accounts)."

        $adminNoMfa = @($reg | Where-Object { $_.isAdmin -eq $true -and $_.isMfaRegistered -eq $false })
        New-Finding -Id 'ENT-USR-004' -Status $(if ($adminNoMfa.Count) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects @($adminNoMfa | ForEach-Object { $_.userPrincipalName })
    }

    # --- Stale accounts -----------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'Stale accounts' -PercentComplete 55
    Invoke-Collector -Name 'Stale accounts' -FindingIds 'ENT-USR-002' -Script {
        $cutoff = $now.AddDays(-$StaleDays)
        $users = @(Get-GraphPagedResult -Uri '/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&$top=500')
        $stale = foreach ($u in ($users | Where-Object { $_.accountEnabled -eq $true })) {
            $dates = @($u.signInActivity.lastSignInDateTime, $u.signInActivity.lastNonInteractiveSignInDateTime, $u.signInActivity.lastSuccessfulSignInDateTime |
                    Where-Object { $_ } | ForEach-Object { ([datetime]$_).ToUniversalTime() })
            if ($dates.Count) {
                $last = ($dates | Measure-Object -Maximum).Maximum
                if ($last -lt $cutoff) { "$($u.userPrincipalName) - last sign-in $($last.ToString('yyyy-MM-dd'))" }
            }
            elseif (([datetime]$u.createdDateTime).ToUniversalTime() -lt $cutoff) {
                "$($u.userPrincipalName) - never signed in (created $(([datetime]$u.createdDateTime).ToString('yyyy-MM-dd')))"
            }
        }
        New-Finding -Id 'ENT-USR-002' -Status $(if (@($stale).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($stale) `
            -Detail "Enabled accounts with no sign-in activity for more than $StaleDays days (of $($users.Count) users)."
    }

    # --- App credentials ----------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'Application credentials' -PercentComplete 70
    Invoke-Collector -Name 'Application credentials' -FindingIds 'ENT-APP-001', 'ENT-APP-002' -Script {
        $select = '$select=id,displayName,appId,passwordCredentials,keyCredentials&$top=999'
        $apps = @(Get-GraphPagedResult -Uri "/v1.0/applications?$select")
        $sps  = @(Get-GraphPagedResult -Uri "/v1.0/servicePrincipals?$select")

        $creds = foreach ($pair in @(@{ Source = 'App registration'; Items = $apps }, @{ Source = 'Enterprise app'; Items = $sps })) {
            foreach ($app in $pair.Items) {
                foreach ($c in @($app.passwordCredentials)) {
                    if ($c.endDateTime) { [pscustomobject]@{ Source = $pair.Source; App = $app.displayName; Type = 'Secret'; End = ([datetime]$c.endDateTime).ToUniversalTime() } }
                }
                foreach ($c in @($app.keyCredentials)) {
                    if ($c.endDateTime) { [pscustomobject]@{ Source = $pair.Source; App = $app.displayName; Type = 'Certificate'; End = ([datetime]$c.endDateTime).ToUniversalTime() } }
                }
            }
        }
        $creds = @($creds)
        $fmt = { "$($_.App) ($($_.Source), $($_.Type)) - $($_.End.ToString('yyyy-MM-dd'))" }

        $expired = @($creds | Where-Object { $_.End -lt $now })
        New-Finding -Id 'ENT-APP-001' -Status $(if ($expired.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($expired | ForEach-Object $fmt)

        $soon = @($creds | Where-Object { $_.End -ge $now -and $_.End -le $now.AddDays($SecretWarningDays) })
        New-Finding -Id 'ENT-APP-002' -Status $(if ($soon.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($soon | ForEach-Object $fmt) `
            -Detail "Credentials expiring within $SecretWarningDays days."
    }

    # --- High-risk application permissions ----------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'High-risk application permissions' -PercentComplete 82
    Invoke-Collector -Name 'Application permissions' -FindingIds 'ENT-APP-003' -Script {
        $graphSp = Invoke-GraphRequestWithRetry -Uri "/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')?`$select=id,appRoles"
        $roleName = @{}
        foreach ($r in $graphSp.appRoles) { $roleName[[string]$r.id] = $r.value }

        $assignments = @(Get-GraphPagedResult -Uri ('/v1.0/servicePrincipals/' + $graphSp.id + '/appRoleAssignedTo?$top=999'))
        $risky = @($assignments | Where-Object { $roleName[[string]$_.appRoleId] -in $highRiskPermissions } |
                ForEach-Object { "$($_.principalDisplayName) - $($roleName[[string]$_.appRoleId])" } | Sort-Object -Unique)
        New-Finding -Id 'ENT-APP-003' -Status $(if ($risky.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $risky `
            -Detail 'Admin-consented Microsoft Graph application permissions from the high-risk list (directory/role/app write, mail, files, sites).'
    }

    # --- Guests in privileged / dynamic groups ------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Status 'Groups and guests' -PercentComplete 92
    Invoke-Collector -Name 'Guest group exposure' -FindingIds 'ENT-GRP-001' -Script {
        $groups = @(Get-GraphPagedResult -Uri '/v1.0/groups?$filter=isAssignableToRole eq true&$select=id,displayName')
        $hits = foreach ($g in $groups) {
            $members = @(Get-GraphPagedResult -Uri ('/v1.0/groups/' + $g.id + '/members?$select=id,userPrincipalName,userType'))
            foreach ($m in ($members | Where-Object { $_.userType -eq 'Guest' })) { "$($g.displayName): $($m.userPrincipalName)" }
        }
        New-Finding -Id 'ENT-GRP-001' -Status $(if (@($hits).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($hits) `
            -Detail "Checked $($groups.Count) role-assignable group(s) for guest members."
    }
    Invoke-Collector -Name 'Dynamic guest groups' -FindingIds 'ENT-GRP-002' -Script {
        $dyn = @(Get-GraphPagedResult -Uri "/v1.0/groups?`$filter=groupTypes/any(c:c eq 'DynamicMembership')&`$select=id,displayName,membershipRule")
        $guestDyn = @($dyn | Where-Object { $_.membershipRule -match 'userType\s+-eq\s+"?Guest' } | ForEach-Object { "$($_.displayName): $($_.membershipRule)" })
        New-Finding -Id 'ENT-GRP-002' -Status $(if ($guestDyn.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $guestDyn `
            -Detail "Checked $($dyn.Count) dynamic group(s). Role-assignable groups cannot be dynamic; confirm what resources these groups grant."
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra ID' -Completed
}
