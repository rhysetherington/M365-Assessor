# Tenant-wide Entra policies from CIS Microsoft 365 Foundations 5.1.x, 5.2.3.x and 5.3.5: who may create security groups, device join
# and local administrator rights, LAPS, application credential restrictions, a few authentication method settings and PIM approval for
# Privileged Role Administrator. Every value is read, never assumed: a property the API does not return makes the check NotAssessed.

function Test-IsoDurationAtMostDays {
    <#
    .SYNOPSIS
        $true when an ISO 8601 duration (P180D, P6M, P1Y ...) is no longer than MaxDays; months count as 30 days and years as 365.
    #>
    param([Parameter(Mandatory)][string]$Duration, [Parameter(Mandatory)][double]$MaxDays)
    [System.Xml.XmlConvert]::ToTimeSpan($Duration).TotalDays -le $MaxDays
}

function Get-AppRestrictionState {
    <#
    .SYNOPSIS
        Evaluates one restriction type (for example passwordAddition) in the application and the service principal halves of the
        default app management policy. Returns the problems found; an empty list means both halves comply.
    #>
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][ValidateSet('passwordCredentials', 'keyCredentials')][string]$Section,
        [Parameter(Mandatory)][string]$RestrictionType,
        [double]$MaxDays = 0
    )
    $problems = @()
    if (-not $Policy.isEnabled) { return @('The default app management policy is switched off') }
    foreach ($side in 'applicationRestrictions', 'servicePrincipalRestrictions') {
        $label = if ($side -eq 'applicationRestrictions') { 'applications' } else { 'service principals' }
        $entry = @($Policy.$side.$Section | Where-Object { $_.restrictionType -eq $RestrictionType }) | Select-Object -First 1
        if (-not $entry -or "$($entry.state)" -ne 'enabled') { $problems += "No enabled '$RestrictionType' restriction for $label"; continue }
        # A start date in the future (or any date after today) means existing and new apps are not covered yet.
        $after = $entry.restrictForAppsCreatedAfterDateTime
        if ($after -and ([datetime]$after) -gt [datetime]::UtcNow) { $problems += "The '$RestrictionType' restriction for $label only applies to apps created after $(([datetime]$after).ToString('yyyy-MM-dd'))" }
        if ($MaxDays -gt 0) {
            if (-not $entry.maxLifetime) { $problems += "The '$RestrictionType' restriction for $label sets no maximum lifetime" }
            elseif (-not (Test-IsoDurationAtMostDays -Duration ([string]$entry.maxLifetime) -MaxDays $MaxDays)) { $problems += "Maximum lifetime for $label is $($entry.maxLifetime), longer than $MaxDays days" }
        }
    }
    $problems
}

function Test-DeviceMembershipRestricted {
    # The membership types are #microsoft.graph.allDeviceRegistrationMembership (everyone), enumerated... (selected) and no... (none).
    param($Membership)
    $type = "$($Membership.'@odata.type')"
    if (-not $type) { throw 'The policy did not return a membership type.' }
    $type -match 'enumeratedDeviceRegistrationMembership$|noDeviceRegistrationMembership$'
}

function Get-EntraTenantPolicyGaps {
    <#
    .SYNOPSIS
        Tenant policy checks from CIS 5.1.x, 5.2.3.x and 5.3.5 (ENT-POL-008/009, ENT-DEV-001..005, ENT-APP-005..008, ENT-AUTH-008..010, ENT-PIM-002).
    #>
    [CmdletBinding()]
    param()

    # --- Default user permissions ---------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Default user permissions' -PercentComplete 60
    Invoke-Collector -Name 'Default user permissions' -FindingIds 'ENT-POL-008', 'ENT-POL-009' -Script {
        $resp = Invoke-GraphRequestWithRetry -Uri '/v1.0/policies/authorizationPolicy'
        $policy = if ($resp.value) { @($resp.value)[0] } else { $resp }
        $perm = $policy.defaultUserRolePermissions
        if ($null -eq $perm) { throw 'The authorization policy returned no default user role permissions.' }
        foreach ($c in @(
                @{ Id = 'ENT-POL-008'; Property = 'allowedToCreateSecurityGroups'; Text = 'Users can create security groups' },
                @{ Id = 'ENT-POL-009'; Property = 'allowedToReadBitlockerKeysForOwnedDevice'; Text = 'Users can read the BitLocker recovery keys of their own devices' })) {
            $value = $perm.($c.Property)
            if ($null -eq $value) { New-Finding -Id $c.Id -Status NotAssessed -Detail "The authorization policy did not return $($c.Property)."; continue }
            New-Finding -Id $c.Id -Status $(if ($value) { 'Gap' } else { 'Pass' }) -AffectedObjects $(if ($value) { @($c.Text) } else { @() }) -Detail "$($c.Property) = $value."
        }
    }

    # --- Device registration policy -----------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Device registration' -PercentComplete 62
    Invoke-Collector -Name 'Device registration policy' -FindingIds 'ENT-DEV-001', 'ENT-DEV-002', 'ENT-DEV-003', 'ENT-DEV-004', 'ENT-DEV-005' -Script {
        # The join and local-administrator settings are only in the beta version of this policy.
        $policy = Invoke-GraphRequestWithRetry -Uri '/beta/policies/deviceRegistrationPolicy'
        $join = $policy.azureADJoin
        if ($null -eq $join) { throw 'The device registration policy returned no Microsoft Entra join settings.' }

        $everyoneJoins = -not (Test-DeviceMembershipRestricted -Membership $join.allowedToJoin)
        New-Finding -Id 'ENT-DEV-001' -Status $(if ($everyoneJoins) { 'Gap' } else { 'Pass' }) `
            -Detail "Who may join devices to Microsoft Entra: $(("$($join.allowedToJoin.'@odata.type')" -replace '^.*\.', '') -replace 'DeviceRegistrationMembership$', '')."

        $quota = $policy.userDeviceQuota
        if ($null -eq $quota) { New-Finding -Id 'ENT-DEV-002' -Status NotAssessed -Detail 'The policy did not return userDeviceQuota.' }
        else { New-Finding -Id 'ENT-DEV-002' -Status $(if ([int]$quota -gt 10) { 'Gap' } else { 'Pass' }) -Detail "Maximum devices per user = $quota (recommended: 10 or fewer)." }

        $enableGa = $join.localAdmins.enableGlobalAdmins
        if ($null -eq $enableGa) { New-Finding -Id 'ENT-DEV-003' -Status NotAssessed -Detail 'The policy did not return localAdmins.enableGlobalAdmins.' }
        else { New-Finding -Id 'ENT-DEV-003' -Status $(if ($enableGa) { 'Gap' } else { 'Pass' }) -Detail "Global Administrators are added as local administrators on joined devices = $enableGa." }

        $everyoneAdmin = -not (Test-DeviceMembershipRestricted -Membership $join.localAdmins.registeringUsers)
        New-Finding -Id 'ENT-DEV-004' -Status $(if ($everyoneAdmin) { 'Gap' } else { 'Pass' }) `
            -Detail "Who becomes a local administrator when they join a device: $(("$($join.localAdmins.registeringUsers.'@odata.type')" -replace '^.*\.', '') -replace 'DeviceRegistrationMembership$', '')."

        $laps = $policy.localAdminPassword.isEnabled
        if ($null -eq $laps) { New-Finding -Id 'ENT-DEV-005' -Status NotAssessed -Detail 'The policy did not return localAdminPassword.isEnabled.' }
        else { New-Finding -Id 'ENT-DEV-005' -Status $(if ($laps) { 'Pass' } else { 'Gap' }) -Detail "Local Administrator Password Solution (LAPS) enabled = $laps." }
    }

    # --- Application credential restrictions --------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Application credential policy' -PercentComplete 64
    Invoke-Collector -Name 'Application credential restrictions' -FindingIds 'ENT-APP-005', 'ENT-APP-006', 'ENT-APP-007', 'ENT-APP-008' -Script {
        $policy = Invoke-GraphRequestWithRetry -Uri '/v1.0/policies/defaultAppManagementPolicy'
        foreach ($c in @(
                @{ Id = 'ENT-APP-005'; Credential = 'passwordCredentials'; Type = 'passwordAddition'; Max = 0; Text = 'Adding client secrets is not blocked' },
                @{ Id = 'ENT-APP-006'; Credential = 'passwordCredentials'; Type = 'passwordLifetime'; Max = 180; Text = 'Client secret lifetime is not limited to 180 days' },
                @{ Id = 'ENT-APP-007'; Credential = 'passwordCredentials'; Type = 'customPasswordAddition'; Max = 0; Text = 'Custom (non-system-generated) secrets are allowed' },
                @{ Id = 'ENT-APP-008'; Credential = 'keyCredentials'; Type = 'asymmetricKeyLifetime'; Max = 180; Text = 'Certificate lifetime is not limited to 180 days' })) {
            $problems = @(Get-AppRestrictionState -Policy $policy -Section $c.Credential -RestrictionType $c.Type -MaxDays $c.Max)
            New-Finding -Id $c.Id -Status $(if ($problems.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $problems `
                -Detail $(if ($problems.Count) { "$($c.Text). Applications and service principals are checked separately." } else { "The default app management policy enforces '$($c.Type)' for applications and service principals." })
        }
    }

    # --- Authentication method settings -------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'Authentication method settings' -PercentComplete 66
    Invoke-Collector -Name 'Authentication method settings' -FindingIds 'ENT-AUTH-008', 'ENT-AUTH-009', 'ENT-AUTH-010' -Script {
        # System-preferred MFA and the Authenticator companion-app setting are only in the beta version of the policy.
        $policy = Invoke-GraphRequestWithRetry -Uri '/beta/policies/authenticationMethodsPolicy'
        $byId = @{}
        foreach ($m in @($policy.authenticationMethodConfigurations)) { $byId[[string]$m.id] = $m }

        $pref = $policy.systemCredentialPreferences
        if ($null -eq $pref) { New-Finding -Id 'ENT-AUTH-008' -Status NotAssessed -Detail 'The policy did not return systemCredentialPreferences.' }
        else {
            $allUsers = @($pref.includeTargets | Where-Object { $_.id -eq 'all_users' }).Count -gt 0
            $ok = "$($pref.state)" -eq 'enabled' -and $allUsers
            $why = if ("$($pref.state)" -eq 'default') { 'it is on the Microsoft-managed default and is not set explicitly' } elseif ("$($pref.state)" -ne 'enabled') { "state = $($pref.state)" } else { 'it does not include all users' }
            $excl = @($pref.excludeTargets | Where-Object { $_ }).Count
            New-Finding -Id 'ENT-AUTH-008' -Status $(if ($ok) { 'Pass' } else { 'Gap' }) `
                -Detail $(if ($ok) { "System-preferred MFA is enabled for all users$(if ($excl) { " ($excl exclusion(s): review that they are documented)" })." } else { "System-preferred MFA is not enabled for all users: $why." })
        }

        $email = $byId['Email']
        if ($null -eq $email) { New-Finding -Id 'ENT-AUTH-009' -Status NotAssessed -Detail 'The policy did not return the Email OTP method.' }
        else { New-Finding -Id 'ENT-AUTH-009' -Status $(if ("$($email.state)" -eq 'disabled') { 'Pass' } else { 'Gap' }) -Detail "Email one-time passcode method state = $($email.state)." }

        $auth = $byId['MicrosoftAuthenticator']
        if ($null -eq $auth) { New-Finding -Id 'ENT-AUTH-010' -Status NotAssessed -Detail 'The policy did not return the Microsoft Authenticator method.' }
        elseif ("$($auth.state)" -ne 'enabled') { New-Finding -Id 'ENT-AUTH-010' -Status Pass -Detail 'The Microsoft Authenticator method is disabled, so the companion-app (Lite) setting does not apply.' }
        else {
            $full = Invoke-GraphRequestWithRetry -Uri '/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/microsoftAuthenticator'
            $companion = $full.featureSettings.companionAppAllowedState.state
            if ($null -eq $companion) { New-Finding -Id 'ENT-AUTH-010' -Status NotAssessed -Detail 'The Authenticator settings did not return featureSettings.companionAppAllowedState.' }
            else {
                New-Finding -Id 'ENT-AUTH-010' -Status $(if ("$companion" -eq 'disabled') { 'Pass' } else { 'Gap' }) `
                    -Detail "Authenticator on companion applications (Authenticator Lite) = $companion$(if ("$companion" -eq 'default') { ' (Microsoft managed: enabled by default)' })."
            }
        }
    }

    # --- PIM approval for Privileged Role Administrator -----------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra policy' -Status 'PIM approval' -PercentComplete 68
    Invoke-Collector -Name 'PIM approval for Privileged Role Administrator' -FindingIds 'ENT-PIM-002' -Script {
        $praTemplateId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        $uri = "/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$praTemplateId'&`$expand=policy(`$expand=rules)"
        $assignment = @(Get-GraphPagedResult -Uri $uri) | Select-Object -First 1
        if (-not $assignment) { throw 'No PIM policy returned for the Privileged Role Administrator role.' }
        $approval = @($assignment.policy.rules) | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' } | Select-Object -First 1
        if (-not $approval) { throw 'The PIM policy has no approval rule.' }
        $required = [bool]$approval.setting.isApprovalRequired
        $approvers = @($approval.setting.approvalStages | ForEach-Object { $_.primaryApprovers } | Where-Object { $_ })
        $ok = $required -and $approvers.Count -gt 0
        New-Finding -Id 'ENT-PIM-002' -Status $(if ($ok) { 'Pass' } else { 'Gap' }) `
            -Detail $(if ($ok) { "Activation needs approval from $($approvers.Count) named approver(s)/group(s)." } elseif (-not $required) { 'Activating Privileged Role Administrator does not require approval.' } else { 'Approval is required but no approvers are named.' })
    }
}
