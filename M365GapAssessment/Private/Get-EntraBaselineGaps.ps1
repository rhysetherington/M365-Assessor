function Test-EmergencyAccessCandidate {
    <#
    .SYNOPSIS
        Decides whether a Global Administrator account looks like an emergency (break-glass) access account.
    .DESCRIPTION
        Receives one record per user who holds a permanent Global Administrator assignment:
            UserPrincipalName      [string]  e.g. breakglass1@contoso.onmicrosoft.com
            DisplayName            [string]
            IsCloudOnlyDomain      [bool]    UPN ends in .onmicrosoft.com
            ExcludedPolicyCount    [int]     enabled Conditional Access policies that exclude this user (directly or via an excluded group)
            EnabledPolicyCount     [int]     enabled Conditional Access policies in the tenant
            LastSignInUtc          [datetime or $null]
        Return $true if the account is a candidate break-glass account, $false if not. Returning $null means "cannot tell"
        and makes the caller report the check as NotAssessed instead of guessing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Candidate)

    # Deliberately lenient and domain-agnostic: clients keep break-glass accounts on either the *.onmicrosoft.com domain or a
    # custom domain, so the UPN suffix (IsCloudOnlyDomain) is NOT used. Being excluded from at least one enabled Conditional
    # Access policy is the signal that someone planned for this account to bypass sign-in controls. This only nominates
    # candidates; whether an account really is break-glass (naming, offline password, monitoring) needs manual review.
    return ($Candidate.ExcludedPolicyCount -gt 0)
}

function Get-EntraBaselineGaps {
    <#
    .SYNOPSIS
        Baseline identity checks derived from CIS Microsoft 365 recommendations that are readable through Graph:
        Security Defaults / MFA baseline, SSPR, smart lockout, password expiry, public groups, emergency access accounts.
    #>
    [CmdletBinding()]
    param()

    # Password Rule Settings only exists once customised; when absent Microsoft's defaults apply (threshold 10, duration 60).
    $script:passwordRuleValues = $null
    $getPasswordRules = {
        if ($null -eq $script:passwordRuleValues) {
            $setting = @(Get-GraphPagedResult -Uri '/v1.0/groupSettings') | Where-Object { $_.displayName -eq 'Password Rule Settings' } | Select-Object -First 1
            $values = @{}
            foreach ($v in @($setting.values)) { $values[[string]$v.name] = [string]$v.value }
            $script:passwordRuleValues = [pscustomobject]@{ Customised = [bool]$setting; Values = $values }
        }
        $script:passwordRuleValues
    }

    # --- Security Defaults / baseline MFA ---------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra baseline' -Status 'Security Defaults' -PercentComplete 5
    Invoke-Collector -Name 'Security Defaults' -FindingIds 'ENT-POL-006' -Script {
        $sdEnabled = Get-SecurityDefaultsState
        if ($null -eq $sdEnabled) { throw 'The Security Defaults policy could not be read.' }
        $caNote = ''
        $mfaForAll = @()
        try {
            $mfaForAll = @(Get-ConditionalAccessPolicies | Where-Object {
                    $_.state -eq 'enabled' -and ($_.conditions.users.includeUsers -contains 'All') -and
                    ($_.conditions.applications.includeApplications -contains 'All') -and (Test-PolicyEnforcesMfa -Policy $_)
                })
        }
        catch { $caNote = ' Conditional Access policies could not be read (licence or permission), so only Security Defaults was evaluated.' }

        $protected = $sdEnabled -or $mfaForAll.Count -gt 0
        $how = if ($sdEnabled) { 'Security Defaults is enabled' } elseif ($mfaForAll.Count) { "Conditional Access MFA for all users: $($mfaForAll.displayName -join ', ')" } else { 'Security Defaults is disabled and no enabled Conditional Access policy requires MFA for all users and apps' }
        # Microsoft recommends Conditional Access over Security Defaults once the tenant is licensed for it (Entra ID P1/P2).
        $licenceNote = if ($sdEnabled -and (Test-TenantCapability -Name 'EntraP1') -eq $true) {
            ' The tenant is licensed for Conditional Access (Entra ID P1/P2) but still relies on Security Defaults; Microsoft recommends Conditional Access for licensed tenants (disable Security Defaults first).'
        } else { '' }
        New-Finding -Id 'ENT-POL-006' -Status $(if ($protected) { 'Pass' } else { 'Gap' }) `
            -AffectedObjects $(if ($protected) { @() } else { @($how) }) -Detail "$how.$caNote$licenceNote"
    }

    # --- SSPR ----------------------------------------------------------------------------------------------
    Invoke-Collector -Name 'Self-service password reset' -FindingIds 'ENT-POL-007' -Script {
        $resp = Invoke-GraphRequestWithRetry -Uri '/v1.0/policies/authorizationPolicy'
        $p = if ($resp.value) { @($resp.value)[0] } else { $resp }
        if ($null -eq $p.allowedToUseSSPR) {
            New-Finding -Id 'ENT-POL-007' -Status NotAssessed -Detail 'The authorization policy did not return allowedToUseSSPR.'
        }
        else {
            New-Finding -Id 'ENT-POL-007' -Status $(if ($p.allowedToUseSSPR) { 'Pass' } else { 'Gap' }) `
                -AffectedObjects $(if ($p.allowedToUseSSPR) { @() } else { @('allowedToUseSSPR = false') }) `
                -Detail 'Tenant-level flag only; confirm the All/Selected scope in Entra admin center > Protection > Password reset.'
        }
    }

    # --- Smart lockout -------------------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra baseline' -Status 'Smart lockout and password expiry' -PercentComplete 30
    Invoke-Collector -Name 'Smart lockout' -FindingIds 'ENT-AUTH-005', 'ENT-AUTH-006' -Script {
        $rules = & $getPasswordRules
        $source = if ($rules.Customised) { 'tenant setting' } else { 'Microsoft default (no custom Password Rule Settings)' }
        $threshold = if ($rules.Values['LockoutThreshold']) { [int]$rules.Values['LockoutThreshold'] } else { 10 }
        $duration = if ($rules.Values['LockoutDurationInSeconds']) { [int]$rules.Values['LockoutDurationInSeconds'] } else { 60 }

        New-Finding -Id 'ENT-AUTH-005' -Status $(if ($threshold -gt 10) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($threshold -gt 10) { @("Lockout threshold = $threshold") } else { @() }) -Detail "Lockout threshold $threshold ($source); expected 10 or fewer."
        New-Finding -Id 'ENT-AUTH-006' -Status $(if ($duration -lt 60) { 'Gap' } else { 'Pass' }) `
            -AffectedObjects $(if ($duration -lt 60) { @("Lockout duration = $duration seconds") } else { @() }) -Detail "Lockout duration $duration seconds ($source); expected 60 or more."
    }

    # --- Password expiry -----------------------------------------------------------------------------------
    Invoke-Collector -Name 'Password expiry' -FindingIds 'ENT-AUTH-007' -Script {
        $never = 2147483647
        $domains = @(Get-GraphPagedResult -Uri '/v1.0/domains?$select=id,isVerified,authenticationType,passwordValidityPeriodInDays')
        $managed = @($domains | Where-Object { $_.isVerified -and $_.authenticationType -eq 'Managed' -and $null -ne $_.passwordValidityPeriodInDays })
        $expiring = @($managed | Where-Object { [int64]$_.passwordValidityPeriodInDays -ne $never } | ForEach-Object { "$($_.id) - passwords expire after $($_.passwordValidityPeriodInDays) days" })
        New-Finding -Id 'ENT-AUTH-007' -Status $(if ($expiring.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $expiring `
            -Detail "$($managed.Count) managed verified domain(s) evaluated (federated domains follow on-premises policy)."
    }

    # --- Public groups -------------------------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra baseline' -Status 'Public groups' -PercentComplete 55
    Invoke-Collector -Name 'Public Microsoft 365 groups' -FindingIds 'ENT-GRP-003' -Script {
        $groups = @(Get-GraphPagedResult -Uri "/v1.0/groups?`$filter=groupTypes/any(c:c eq 'Unified')&`$select=id,displayName,visibility,createdDateTime&`$top=999")
        $public = @($groups | Where-Object { $_.visibility -eq 'Public' } |
                ForEach-Object { "$($_.displayName) - created $(([datetime]$_.createdDateTime).ToString('yyyy-MM-dd'))" })
        New-Finding -Id 'ENT-GRP-003' -Status $(if ($public.Count) { 'Gap' } else { 'Pass' }) -AffectedObjects $public `
            -Detail "$($public.Count) of $($groups.Count) Microsoft 365 group(s) are public. Each must be a deliberately approved public group."
    }

    # --- Emergency access accounts ----------------------------------------------------------------------
    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra baseline' -Status 'Emergency access accounts' -PercentComplete 75
    Invoke-Collector -Name 'Emergency access accounts' -FindingIds 'ENT-CA-009' -Script {
        $policies = @(Get-ConditionalAccessPolicies | Where-Object { $_.state -eq 'enabled' })

        # Expand excluded groups once so group-based exclusions count for their members.
        $groupMembers = @{}
        foreach ($gid in @($policies | ForEach-Object { $_.conditions.users.excludeGroups } | Where-Object { $_ } | Sort-Object -Unique)) {
            $groupMembers[[string]$gid] = @(Get-GraphPagedResult -Uri ('/v1.0/groups/' + $gid + '/members?$select=id') | ForEach-Object { [string]$_.id })
        }

        $instances = @(Get-GraphPagedResult -Uri '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal,roleDefinition')
        $admins = @($instances | Where-Object {
                $_.assignmentType -eq 'Assigned' -and $null -eq $_.endDateTime -and
                $_.roleDefinition.displayName -eq 'Global Administrator' -and $_.principal.'@odata.type' -eq '#microsoft.graph.user'
            } | ForEach-Object { $_.principal } | Sort-Object id -Unique)

        $candidates = foreach ($u in $admins) {
            $excluded = @($policies | Where-Object {
                    ($_.conditions.users.excludeUsers -contains $u.id) -or
                    (@($_.conditions.users.excludeGroups | Where-Object { $_ -and ($groupMembers[[string]$_] -contains [string]$u.id) }).Count -gt 0)
                }).Count
            [pscustomobject]@{
                UserPrincipalName   = $u.userPrincipalName
                DisplayName         = $u.displayName
                IsCloudOnlyDomain   = [bool]($u.userPrincipalName -like '*.onmicrosoft.com')
                ExcludedPolicyCount = $excluded
                EnabledPolicyCount  = $policies.Count
                LastSignInUtc       = $null
            }
        }

        $verdicts = @($candidates | ForEach-Object { Test-EmergencyAccessCandidate -Candidate $_ })
        if ($verdicts | Where-Object { $null -eq $_ }) {
            New-Finding -Id 'ENT-CA-009' -Status NotAssessed -Detail 'The emergency-access rule could not decide for at least one account (Test-EmergencyAccessCandidate returned $null).'
        }
        else {
            $found = @($candidates | Where-Object { Test-EmergencyAccessCandidate -Candidate $_ } | ForEach-Object {
                    "$($_.UserPrincipalName) (excluded from $($_.ExcludedPolicyCount) of $($_.EnabledPolicyCount) enabled Conditional Access policies)"
                })
            New-Finding -Id 'ENT-CA-009' -Status $(if ($found.Count -ge 2) { 'Pass' } else { 'Gap' }) `
                -AffectedObjects $(if ($found.Count -ge 2) { @() } else { @("Identified $($found.Count) candidate emergency access account(s); at least 2 expected") }) `
                -Detail ("Heuristic over $($candidates.Count) permanent Global Administrator(s): an account counts as a candidate if an enabled Conditional Access policy excludes it. " +
                    "Candidates (confirm manually that they really are break-glass accounts): $(if ($found.Count) { $found -join '; ' } else { 'none' }).")
        }
    }

    Write-Progress -Id 2 -ParentId 1 -Activity 'Entra baseline' -Completed
}
