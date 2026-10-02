function Get-EntraPolicyGaps {
    <#
    .SYNOPSIS
        Entra ID tenant-policy collector: consent and user settings, authentication methods, Conditional Access depth,
        PIM role settings, guest and external access, hybrid sync, Identity Protection and governance.
    #>
    [CmdletBinding()]
    param([int]$StaleDays = 90)

    $now = [datetime]::UtcNow
    $globalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    $memberLikeGuestRoleId = 'a0b1b346-4d3e-4e8b-98f8-753987be4970'
    $riskyDelegatedScopes = @(
        'Directory.AccessAsUser.All', 'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All',
        'User.ReadWrite.All', 'Group.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All', 'Sites.FullControl.All',
        'full_access_as_user', 'EWS.AccessAsUser.All'
    )

    # --- Authorization policy: user consent, app creation, guest settings --------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Authorization policy' -PercentComplete 5
    Invoke-Collector -Name 'Authorization policy' -FindingIds 'ENT-POL-001', 'ENT-POL-003', 'ENT-POL-004', 'ENT-POL-005' -Script {
        $resp = Invoke-GraphRequestWithRetry -Uri '/v1.0/policies/authorizationPolicy'
        $p = if ($resp.value) { @($resp.value)[0] } else { $resp }
        $perm = $p.defaultUserRolePermissions

        $grantPolicies = @($perm.permissionGrantPoliciesAssigned)
        $legacy = $grantPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
        New-Finding -Id 'ENT-POL-001' -Status $(if ($legacy) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($legacy) { @('User consent policy: microsoft-user-default-legacy (allow all apps)') } else { @() }) `
            -Detail "Assigned user consent policies: $(if ($grantPolicies.Count) { $grantPolicies -join ', ' } else { 'none (users cannot consent)' })"

        $loose = @()
        if ($perm.allowedToCreateApps) { $loose += 'Users can register applications' }
        if ($perm.allowedToCreateTenants) { $loose += 'Users can create tenants' }
        New-Finding -Id 'ENT-POL-003' -Status $(if ($loose.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $loose

        New-Finding -Id 'ENT-POL-004' -Status $(if ($p.allowInvitesFrom -eq 'everyone') { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($p.allowInvitesFrom -eq 'everyone') { @('allowInvitesFrom = everyone') } else { @() }) `
            -Detail "Guest invitations allowed from: $($p.allowInvitesFrom)"

        $memberLike = $p.guestUserRoleId -eq $memberLikeGuestRoleId
        New-Finding -Id 'ENT-POL-005' -Status $(if ($memberLike) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($memberLike) { @('Guest user role = same access as members') } else { @() })
    }

    Invoke-Collector -Name 'Admin consent workflow' -FindingIds 'ENT-POL-002' -Script {
        $acp = Invoke-GraphRequestWithRetry -Uri '/v1.0/policies/adminConsentRequestPolicy'
        New-Finding -Id 'ENT-POL-002' -Status $(if ($acp.isEnabled) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($acp.isEnabled) { @() } else { @('Admin consent request workflow is disabled') })
    }

    # --- Delegated tenant-wide consent --------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Delegated permission grants' -PercentComplete 15
    Invoke-Collector -Name 'Delegated consent' -FindingIds 'ENT-APP-004' -Script {
        $grants = @(Get-GraphPagedResult -Uri '/v1.0/oauth2PermissionGrants' | Where-Object { $_.consentType -eq 'AllPrincipals' })
        $names = @{}
        foreach ($sp in @(Get-GraphPagedResult -Uri '/v1.0/servicePrincipals?$select=id,displayName&$top=999')) { $names[[string]$sp.id] = $sp.displayName }
        $hits = foreach ($g in $grants) {
            $scopes = @(([string]$g.scope).Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries) | Where-Object { $_ -in $riskyDelegatedScopes })
            if ($scopes.Count) { "$($names[[string]$g.clientId]) - $($scopes -join ', ')" }
        }
        New-Finding -Id 'ENT-APP-004' -Status $(if (@($hits).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($hits) `
            -Detail "Checked $($grants.Count) tenant-wide delegated grant(s)."
    }

    # --- Authentication methods ---------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Authentication methods' -PercentComplete 28
    Invoke-Collector -Name 'Authentication methods' -FindingIds 'ENT-AUTH-001', 'ENT-AUTH-002', 'ENT-AUTH-003' -Script {
        # The configurations are not addressable as a collection; the policy returns them inline (id + state),
        # and individual methods can be fetched by id for feature settings.
        $policy = Invoke-GraphRequestWithRetry -Uri '/v1.0/policies/authenticationMethodsPolicy'
        $byId = @{}
        foreach ($c in @($policy.authenticationMethodConfigurations)) { $byId[[string]$c.id] = $c }
        if ($byId['MicrosoftAuthenticator'].state -eq 'enabled') {
            $byId['MicrosoftAuthenticator'] = Invoke-GraphRequestWithRetry -Uri '/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator'
        }

        $weak = @('Sms', 'Voice') | Where-Object { $byId[$_].state -eq 'enabled' }
        New-Finding -Id 'ENT-AUTH-001' -Status $(if (@($weak).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($weak | ForEach-Object { "$_ authentication is enabled" })

        $ma = $byId['MicrosoftAuthenticator']
        $maIssues = @()
        if ($ma.state -ne 'enabled') { $maIssues += 'Microsoft Authenticator method is disabled' }
        elseif ($ma.featureSettings.numberMatchingRequiredState.state -eq 'disabled') { $maIssues += 'Number matching is disabled' }
        New-Finding -Id 'ENT-AUTH-002' -Status $(if ($maIssues.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $maIssues

        $strong = @('Fido2', 'X509Certificate') | Where-Object { $byId[$_].state -eq 'enabled' }
        New-Finding -Id 'ENT-AUTH-003' -Status $(if (@($strong).Count) { 'Pass' } else { 'Gap' }) `
            -Detail $(if (@($strong).Count) { "Enabled: $(@($strong) -join ', ')" } else { 'Neither FIDO2 nor certificate-based authentication is enabled (Windows Hello for Business is configured outside this policy).' })
    }

    Invoke-Collector -Name 'Password protection' -FindingIds 'ENT-AUTH-004' -Script {
        # Tenant settings are listed under /groupSettings; 'Password Rule Settings' only exists once customised.
        $setting = @(Get-GraphPagedResult -Uri '/v1.0/groupSettings') | Where-Object { $_.displayName -eq 'Password Rule Settings' } | Select-Object -First 1
        $values = @{}
        foreach ($v in @($setting.values)) { $values[[string]$v.name] = [string]$v.value }
        $enabled = $values['EnableBannedPasswordCheck'] -eq 'True' -and -not [string]::IsNullOrWhiteSpace($values['BannedPasswordList'])
        New-Finding -Id 'ENT-AUTH-004' -Status $(if ($enabled) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($enabled) { @() } else { @('Custom banned password list is not enabled or empty') }) `
            -Detail 'The Microsoft global banned password list is always applied; this checks the organisation-specific list.'
    }

    # --- Conditional Access depth -------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Conditional Access depth' -PercentComplete 42
    Invoke-Collector -Name 'Conditional Access depth' -FindingIds 'ENT-CA-005', 'ENT-CA-006', 'ENT-CA-007', 'ENT-CA-008' -Script {
        $enabled = @(Get-GraphPagedResult -Uri '/v1.0/identity/conditionalAccess/policies' | Where-Object { $_.state -eq 'enabled' })
        $locations = @(Get-GraphPagedResult -Uri '/v1.0/identity/conditionalAccess/namedLocations')

        $device = @($enabled | Where-Object { ($_.grantControls.builtInControls -contains 'compliantDevice') -or ($_.grantControls.builtInControls -contains 'domainJoinedDevice') })
        New-Finding -Id 'ENT-CA-005' -Status $(if ($device.Count) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($device.Count) { "Enforced by: $($device.displayName -join ', ')" } else { 'No enabled policy requires a compliant or hybrid-joined device.' })

        $guestMfa = @($enabled | Where-Object {
                (($_.conditions.users.includeUsers -contains 'All') -or ($null -ne $_.conditions.users.includeGuestsOrExternalUsers)) -and
                (($_.grantControls.builtInControls -contains 'mfa') -or ($null -ne $_.grantControls.authenticationStrength))
            })
        New-Finding -Id 'ENT-CA-006' -Status $(if ($guestMfa.Count) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($guestMfa.Count) { "Covered by: $($guestMfa.displayName -join ', ')" } else { 'No enabled policy applies MFA to all users or to guest/external users.' })

        if ((Test-TenantCapability -Name 'EntraP2') -eq $false) {
            New-Finding -Id 'ENT-CA-007' -Status NotAssessed -Detail 'Risk-based Conditional Access requires Entra ID P2 (Identity Protection).'
        }
        else {
            $risk = @($enabled | Where-Object { (Test-HasItems $_.conditions.signInRiskLevels) -or (Test-HasItems $_.conditions.userRiskLevels) })
            New-Finding -Id 'ENT-CA-007' -Status $(if ($risk.Count) { 'Pass' } else { 'Gap' }) `
                -Detail $(if ($risk.Count) { "Risk-based policies: $($risk.displayName -join ', ')" } else { 'No enabled policy uses sign-in risk or user risk conditions.' })
        }

        $usesLocation = @($enabled | Where-Object { $null -ne $_.conditions.locations })
        $hasLocationControl = $locations.Count -gt 0 -and $usesLocation.Count -gt 0
        New-Finding -Id 'ENT-CA-008' -Status $(if ($hasLocationControl) { 'Pass' } else { 'Gap' }) `
            -Detail "$($locations.Count) named location(s); $($usesLocation.Count) enabled policy(ies) use location conditions."
    }

    # --- PIM role settings for Global Administrator -------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'PIM role settings' -PercentComplete 55
    Invoke-Collector -Name 'PIM role settings' -FindingIds 'ENT-PIM-001' -Script {
        $uri = "/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$globalAdminTemplateId'&`$expand=policy(`$expand=rules)"
        $assignment = @(Get-GraphPagedResult -Uri $uri) | Select-Object -First 1
        if (-not $assignment) { throw 'No PIM policy returned for the Global Administrator role.' }
        $rules = @($assignment.policy.rules)
        $enablement = $rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }
        $authContext = $rules | Where-Object { $_.id -eq 'AuthenticationContext_EndUser_Assignment' }
        $expiration = $rules | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' }
        $approval = $rules | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' }

        $issues = @()
        if (-not (($enablement.enabledRules -contains 'MultiFactorAuthentication') -or $authContext.isEnabled)) { $issues += 'Activation does not require MFA or an authentication context' }
        if ($expiration.maximumDuration) {
            $hours = [System.Xml.XmlConvert]::ToTimeSpan([string]$expiration.maximumDuration).TotalHours
            if ($hours -gt 8) { $issues += "Maximum activation duration is $hours hours (recommended: 8 or less)" }
        }
        $approvalText = if ($approval.setting.isApprovalRequired) { 'required' } else { 'not required' }
        New-Finding -Id 'ENT-PIM-001' -Status $(if ($issues.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $issues `
            -Detail "Approval for activation is $approvalText (not scored; recommended where more than one Global Administrator exists)."
    }

    # --- Guests and external access -----------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Guests and external access' -PercentComplete 68
    Invoke-Collector -Name 'Cross-tenant access' -FindingIds 'ENT-EXT-001' -Script {
        $default = Invoke-GraphRequestWithRetry -Uri '/v1.0/policies/crossTenantAccessPolicy/default'
        $partners = @(Get-GraphPagedResult -Uri '/v1.0/policies/crossTenantAccessPolicy/partners')
        $inbound = $default.b2bCollaborationInbound.usersAndGroups
        $openToAll = ($inbound.accessType -eq 'allowed') -and (@($inbound.targets | Where-Object { $_.target -eq 'AllUsers' }).Count -gt 0)
        $gap = $openToAll -and $partners.Count -eq 0
        New-Finding -Id 'ENT-EXT-001' -Status $(if ($gap) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($gap) { @('Default: inbound B2B collaboration allowed for all users from all organisations', 'No partner-specific cross-tenant policies configured') } else { @() }) `
            -Detail "$($partners.Count) partner configuration(s)."
    }

    Invoke-Collector -Name 'Guest accounts' -FindingIds 'ENT-EXT-003' -Script {
        $cutoff = $now.AddDays(-$StaleDays)
        $pendingCutoff = $now.AddDays(-30)
        $guests = @(Get-GraphPagedResult -Uri '/v1.0/users?$filter=userType eq ''Guest''&$select=id,displayName,userPrincipalName,mail,createdDateTime,externalUserState,signInActivity&$top=500')
        $hits = foreach ($g in $guests) {
            $created = ([datetime]$g.createdDateTime).ToUniversalTime()
            $label = if ($g.mail) { $g.mail } else { $g.userPrincipalName }
            if ($g.externalUserState -eq 'PendingAcceptance' -and $created -lt $pendingCutoff) { "$label - invitation pending since $($created.ToString('yyyy-MM-dd'))"; continue }
            $dates = @($g.signInActivity.lastSignInDateTime, $g.signInActivity.lastNonInteractiveSignInDateTime, $g.signInActivity.lastSuccessfulSignInDateTime |
                    Where-Object { $_ } | ForEach-Object { ([datetime]$_).ToUniversalTime() })
            if ($dates.Count) {
                $last = ($dates | Measure-Object -Maximum).Maximum
                if ($last -lt $cutoff) { "$label - last sign-in $($last.ToString('yyyy-MM-dd'))" }
            }
            elseif ($created -lt $cutoff) { "$label - never signed in (created $($created.ToString('yyyy-MM-dd')))" }
        }
        New-Finding -Id 'ENT-EXT-003' -Status $(if (@($hits).Count) { 'Gap' } else { 'Pass' }) -AffectedObjects @($hits) `
            -Detail "$($guests.Count) guest account(s) evaluated; stale threshold $StaleDays days, pending invitations older than 30 days."
    }

    # --- Hybrid sync --------------------------------------------------------------------------------
    Invoke-Collector -Name 'Directory sync' -FindingIds 'ENT-HYB-001' -Script {
        $org = @((Invoke-GraphRequestWithRetry -Uri '/v1.0/organization?$select=id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime').value)[0]
        if (-not $org.onPremisesSyncEnabled) {
            New-Finding -Id 'ENT-HYB-001' -Status Pass -Detail 'Cloud-only tenant (directory synchronisation not enabled).'
        }
        else {
            $last = if ($org.onPremisesLastSyncDateTime) { ([datetime]$org.onPremisesLastSyncDateTime).ToUniversalTime() } else { $null }
            $stale = (-not $last) -or ($last -lt $now.AddHours(-24))
            New-Finding -Id 'ENT-HYB-001' -Status $(if ($stale) { 'Gap' } else { 'Pass' }) `
                -AffectedObjects $(if ($stale) { @("Last directory sync: $(if ($last) { $last.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'never' })") } else { @() })
        }
    }

    # --- Identity Protection and governance ---------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Identity Protection' -PercentComplete 82
    Invoke-Collector -Name 'Risky users' -FindingIds 'ENT-RISK-001' -Script {
        $risky = @(Get-GraphPagedResult -Uri "/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'&`$top=500")
        New-Finding -Id 'ENT-RISK-001' -Status $(if ($risky.Count) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects @($risky | ForEach-Object { "$($_.userPrincipalName) - risk level $($_.riskLevel)" })
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Governance' -PercentComplete 92
    Invoke-Collector -Name 'Access reviews' -FindingIds 'ENT-GOV-001' -Script {
        $reviews = @(Get-GraphPagedResult -Uri '/v1.0/identityGovernance/accessReviews/definitions?$top=100')
        New-Finding -Id 'ENT-GOV-001' -Status $(if ($reviews.Count) { 'Pass' } else { 'Gap' }) -Detail "$($reviews.Count) access review definition(s)."
    }
    Invoke-Collector -Name 'Terms of use' -FindingIds 'ENT-GOV-002' -Script {
        $agreements = @(Get-GraphPagedResult -Uri '/v1.0/identityGovernance/termsOfUse/agreements')
        New-Finding -Id 'ENT-GOV-002' -Status $(if ($agreements.Count) { 'Pass' } else { 'Gap' }) -Detail "$($agreements.Count) Terms of use agreement(s)."
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Completed
}
